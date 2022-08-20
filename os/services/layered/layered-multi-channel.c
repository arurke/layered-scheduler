#include "contiki.h"
#include "layered.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/packetbuf.h"
#include "net/routing/routing.h"
#include "sys/node-id.h"
#include "rpl.h"
#include "rpl-private.h"
#include "uip-icmp6.h"
#include "lib/random.h"
#include "packet-type.h"
#include <inttypes.h>

/*---------------------------------------------------------------------------*/

#include "sys/log.h"
#define LOG_MODULE "Layered"
#define LOG_LEVEL   LOG_LEVEL_LAYERED

/*---------------------------------------------------------------------------*/

#ifndef BUILD_WITH_PACKET_TYPE
#error Layered requires BUILD_WITH_PACKET_TYPE
#endif

#if ROUTING_CONF_RPL_LITE
#error Layered supports only RPL CLASSIC
#endif

/*---------------------------------------------------------------------------*/

typedef struct {
  uint16_t node_depth;
  uint8_t node_layer;
  uint16_t child_depth;
  uint8_t child_layer;
} layered_status_t;

static layered_status_t current_status = {
    .node_depth = 0xffff,
    .node_layer = 0xff,
    .child_depth = 0xffff,
    .child_layer = 0xff,
};

static uint16_t slotframe_handle = 0;
static struct tsch_slotframe *sf_layered;

#define COMMON_CELL_CHANNEL   1
#define NUM_CHANNELS          LAYERED_NUM_CHANNELS
#define CHANNELS              LAYERED_CHANNELS
// Avoid channel offset 0 due to stats not supporting it.
static uint8_t channels[NUM_CHANNELS] = CHANNELS;

// For gruesome source addr heuristics
#define HOP_LIMIT_MASK            0x03
#define SIXLO_HEADER_PART2_OFFSET 1
#define SRC_ADDR_MODE_MASK        0x30
#define SRC_ADDR_OFFSET           3

#define FIRST_COMMON_SLOT         (COMMON_SLOT_SPACING - 1)
#define COMMON_SLOT_OPTIONS       (LINK_OPTION_RX | LINK_OPTION_TX | LINK_OPTION_SHARED)

#if LAYERED_STATS && !LAYERED_STATEFUL
#define STATS_NUM_LINKS   50
typedef struct {
  uint16_t timeslot;
  uint16_t channel;
  uint8_t options;
  bool active;
  uint32_t tx_attempts;
  uint32_t no_ok_mac;
} layered_stats_t;

static layered_stats_t layered_stats[STATS_NUM_LINKS] = {{0}};
static uint32_t unknown_stats = 0;

void layered_stats_update(struct tsch_neighbor *n, struct tsch_packet *p,
                          struct tsch_link *link, uint8_t channel_offset,
                          uint8_t mac_tx_status) {

  for(int i = 0; i < STATS_NUM_LINKS; i++) {
    if(layered_stats[i].timeslot == link->timeslot &&
        layered_stats[i].channel == channel_offset) {

      layered_stats[i].tx_attempts++;

      if(mac_tx_status != MAC_TX_OK) {
        layered_stats[i].no_ok_mac++;
      }

      return;
    }
  }
  unknown_stats++;
}

void layered_print_stats() {
  tsch_schedule_print();

  LOG_INFO("Printing stats:\n");
  int i = 0;
  uint8_t num_links = 0;
  for(i = 0; i < STATS_NUM_LINKS; i++) {
    if(layered_stats[i].timeslot != 0 &&
        layered_stats[i].channel != 0) {

      num_links++;

      if(layered_stats[i].options & LINK_OPTION_SHARED) {
        LOG_INFO("BC: ");
      }
      else {
        LOG_INFO("UC: ");
      }
      LOG_INFO_("TS/CH %" PRIu16 "/%" PRIu16 ": %" PRIu32 " attempts, " \
               " %" PRIu32 " no OK status",
               layered_stats[i].timeslot,
               layered_stats[i].channel,
               layered_stats[i].tx_attempts,
               layered_stats[i].no_ok_mac);
      LOG_INFO_("%s\n", layered_stats[i].active ? "" : " - inactive");
    }
  }

  LOG_INFO("Num links: %" PRIu8 "\n", num_links);

  if(unknown_stats != 0) {
    LOG_ERR("Unknown stats %" PRIu32 "\n", unknown_stats);
  }
}

static void stats_add_link(
    uint16_t timeslot, uint16_t channel, uint8_t options) {
  for(int i = 0; i < STATS_NUM_LINKS; i++) {
    if(layered_stats[i].timeslot == timeslot &&
           layered_stats[i].channel == channel) {
      layered_stats[i].options = options;
      layered_stats[i].active = true;
      // Already exists;
      return;
    }

    if(layered_stats[i].timeslot == 0 &&
        layered_stats[i].channel == 0) {
      layered_stats[i].timeslot = timeslot;
      layered_stats[i].channel = channel;
      layered_stats[i].options = options;
      layered_stats[i].active = true;
      return;
    }
  }
  LOG_ERR("Stats is full!\n");
}

static void stats_deactivate_link(
    uint16_t timeslot, uint16_t channel) {
  for(int i = 0; i < STATS_NUM_LINKS; i++) {
    if(layered_stats[i].timeslot == timeslot &&
           layered_stats[i].channel == channel) {
      layered_stats[i].active = false;
      return;
    }
  }
}
#endif /* LAYERED_STATS */

#if LAYERED_STATEFUL
static bool schedule_in_sync(void);
static void sync_links_with_schedule(void);

typedef struct {
  bool occupied;
  uint16_t timeslot;
  uint16_t channel;
  uint8_t options;
  enum link_type link_type;
  linkaddr_t address;
  bool is_flow;
  bool should_be_scheduled;
  bool scheduled;
#if LAYERED_STATS
  uint32_t tx_attempts;
  uint32_t no_ok_mac;
#endif
} layered_link_t;

// This also includes RX links
#define MAX_NUM_LINKS   100

static layered_link_t layered_links[MAX_NUM_LINKS] = {{0}};

#if LAYERED_STATS
static uint32_t unknown_stats = 0;
void layered_stats_update(struct tsch_neighbor *n, struct tsch_packet *p,
                          struct tsch_link *link, uint8_t channel_offset,
                          uint8_t mac_tx_status) {

  // (channel offset in link cannot be trusted when TSCH_WITH_LINK_SELECTOR)
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].timeslot == link->timeslot &&
        layered_links[i].channel == channel_offset &&
        layered_links[i].options != LINK_OPTION_RX) {

      layered_links[i].tx_attempts++;

      if(mac_tx_status != MAC_TX_OK) {
        layered_links[i].no_ok_mac++;
      }

      return;
    }
  }
  unknown_stats++;
}

void layered_print_stats() {
  tsch_schedule_print();

  LOG_INFO("Printing stats:\n");
  int i = 0;
  uint8_t num_links = 0;
  for(i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].timeslot != 0 &&
        layered_links[i].channel != 0) {

      num_links++;

      if(layered_links[i].options & LINK_OPTION_SHARED) {
        LOG_INFO("BC: ");
      }
      else {
        LOG_INFO("UC: ");
      }
      LOG_INFO_("TS/CH %" PRIu16 "/%" PRIu16 ": %" PRIu32 " attempts, " \
               " %" PRIu32 " no OK",
               layered_links[i].timeslot,
               layered_links[i].channel,
               layered_links[i].tx_attempts,
               layered_links[i].no_ok_mac);
      LOG_INFO_("%s ", layered_links[i].scheduled ? "" : " - not-sched.");
      LOG_INFO_("%s\n",
                layered_links[i].scheduled !=
                    layered_links[i].should_be_scheduled ? " - not in sync" : "");
    }
  }

  LOG_INFO("Num links: %" PRIu8 "\n", num_links);

  if(unknown_stats != 0) {
    LOG_ERR("Unknown stats %" PRIu32 "\n", unknown_stats);
  }

#if LAYERED_STATEFUL
  // Utilize the periodic printing to check our sync
  // TODO is it fast enough?
  if(!schedule_in_sync()) {
    LOG_WARN("Schedule not in sync\n");
    sync_links_with_schedule();
  }
#endif

}
#endif /* LAYERED_STATS */

// Returns link matching the timeslot/channel
static layered_link_t* get_link(uint16_t timeslot, uint16_t channel) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].timeslot == timeslot &&
        layered_links[i].channel == channel) {
      return &layered_links[i];
    }
  }
  return NULL;
}

// Returns the link matching all fields
static layered_link_t* get_identical_link(
    uint16_t timeslot, uint16_t channel,
    uint8_t options, enum link_type link_type,
    const linkaddr_t* address, bool is_flow) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].timeslot == timeslot &&
        layered_links[i].channel == channel &&
        layered_links[i].options == options &&
        layered_links[i].link_type == link_type &&
        (linkaddr_cmp(&(layered_links[i].address), address) != 0) &&
        layered_links[i].is_flow == is_flow) {
      return &layered_links[i];
    }
  }
  return NULL;
}

static bool link_is_enabled(const layered_link_t* link) {
  return link->scheduled || link->should_be_scheduled;
}

static uint8_t get_available_index(void) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(!layered_links[i].occupied) {
      return i;
    }
  }

  // If no open places in list, find an abandoned link
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(!layered_links[i].scheduled && !layered_links[i].should_be_scheduled) {
      return i;
    }
  }

  // Nothing available!
  return MAX_NUM_LINKS+1;
}

static bool schedule_in_sync(void) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].scheduled != layered_links[i].should_be_scheduled) {
      return false;
    }
  }
  return true;
}

static void remove_link(uint16_t timeslot, uint16_t channel) {
  layered_link_t* existing_link = get_link(timeslot, channel);
  if(existing_link == NULL) {
    LOG_WARN("Unable to remove non-existing link %u/%u\n", timeslot, channel);
    return;
  }
  else {
    existing_link->should_be_scheduled = false;
    LOG_DBG("Link %u/%u removed\n", timeslot, channel);
  }

  sync_links_with_schedule();
}

static void add_link(
    uint16_t timeslot, uint16_t channel,
    uint8_t options, enum link_type link_type,
    const linkaddr_t* address, bool is_flow) {

  // Check if identical already exists
  layered_link_t* link =
      get_identical_link(timeslot, channel, options, link_type, address, is_flow);
  if(link != NULL) {
    if(!link_is_enabled(link)) {
      link->should_be_scheduled = true;
      LOG_DBG("Link %u/%u already in place, enabling\n", timeslot, channel);
    }
    else {
      LOG_DBG("Link %u/%u already in place and enabled\n", timeslot, channel);
    }
    return;
  }

  // Add new link
  layered_link_t new_link =
    { .occupied = true,
      .timeslot = timeslot,
      .channel = channel,
      .options = options,
      .link_type = link_type,
      .is_flow = is_flow,
      .should_be_scheduled = true,
      .scheduled = false};

  linkaddr_copy(&new_link.address, address);

  layered_link_t* existing_link = get_link(timeslot, channel);
  if(existing_link != NULL) {
    *existing_link = new_link;
  }
  else {
    uint8_t new_link_index = get_available_index();
    if(new_link_index > MAX_NUM_LINKS) {
      LOG_ERR("No room for more links!\n");
      return;
    }
    else {
      layered_links[new_link_index] = new_link;
    }
  }

  LOG_DBG("Link %u/%u added\n", timeslot, channel);
}

static void sync_links_with_schedule(void) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(!layered_links[i].occupied) {
      continue;
    }

    // Check if link is out of sync
    if(layered_links[i].scheduled != layered_links[i].should_be_scheduled) {
      // Unschedule link
      if(!layered_links[i].should_be_scheduled) {
        int res =
            tsch_schedule_remove_link_by_timeslot(sf_layered,
                                                  layered_links[i].timeslot,
                                                  layered_links[i].channel);
        if(!res) {
          LOG_WARN("Failed to unschedule link %u/%u\n",
                  layered_links[i].timeslot, layered_links[i].channel);
        }
        else {
          LOG_DBG("Link %u/%u un-scheduled\n",
                  layered_links[i].timeslot, layered_links[i].channel);
          layered_links[i].scheduled = false;
        }
      }
      // Schedule link
      else {
        struct tsch_link* link =
            tsch_schedule_add_link(sf_layered,layered_links[i].options,
                                   layered_links[i].link_type,
                                   &layered_links[i].address,
                                   layered_links[i].timeslot,
                                   layered_links[i].channel, 1,
                                   layered_links[i].is_flow);
        if(link == NULL) {
          LOG_WARN("Failed to schedule link %u/%u\n",
                  layered_links[i].timeslot, layered_links[i].channel);
        }
        else {
          LOG_DBG("Link %u/%u scheduled\n",
                  layered_links[i].timeslot, layered_links[i].channel);
          layered_links[i].scheduled = true;
        }
      }
    }
  }
}

#endif /* LAYERED_STATEFUL */

/*---------------------------------------------------------------------------*/
static uint16_t
get_node_timeslot(const linkaddr_t *addr)
{
  if(addr != NULL && LAYERED_MAX_NUM_NODES > 0) {
    // +1 as we assume the last node will ID equal to the max num nodes
    // see also 0-index comment in calculate_layered_timeslot()
    return LAYERED_LINKADDR_HASH(addr) % (LAYERED_MAX_NUM_NODES + 1);
  } else {
    return 0xffff;
  }
}

/*---------------------------------------------------------------------------*/
static uint16_t
calculate_channel(uint8_t depth)
{
  // Treat root as on depth 1
  if(depth == 0) {
    depth = 1;
  }

  // -1 for arithmetic simplicity such that bottom is 0
  uint16_t channel = ((depth-1) / LAYERED_NUM_LAYERS) % NUM_CHANNELS;

  // Fetch actual channel from
  channel = channels[channel];

  return channel;
}
/*---------------------------------------------------------------------------*/
static uint16_t
calculate_layered_timeslot(const linkaddr_t *linkaddr, uint16_t layer) {
  // Hash of node id
  uint16_t timeslot = get_node_timeslot(linkaddr);

  if(timeslot == 0xffff) {
    LOG_ERR("Lay!: Panic! Unable to calculate timeslot! TEST FAILED\n");
    return 0xffff;
  }

  // TODO Because timeslots are 0-indexed
  timeslot--;

  // Shift right into correct layer
  timeslot += (LAYERED_NUM_LAYERS - layer) * LAYERED_MAX_NUM_NODES;

  // Shift to accommodate any common slots. -1 due to ts being 0-index
  uint16_t num_common_slots_so_far = timeslot / (COMMON_SLOT_SPACING - 1);
  timeslot += num_common_slots_so_far;

  return timeslot;
}

static bool
find_source_address(
    const uint8_t* data, uint16_t data_len, linkaddr_t* source_lladdr) {
  // Hack to figure out the originating node address

  if(data_len < 12) {
    LOG_ERR("Too short for source address!\n");
    return false;
  }

//  LOG_DBG("Len: %u. Hex:", data_len);
//  for(int i = 0; i < data_len; i++) {
//    LOG_DBG_("%02x", data[i]);
//  }
//  LOG_DBG_("\n");

  // Is source address compressed? If yes, we are transmitting
  if(((*(data + SIXLO_HEADER_PART2_OFFSET)) & SRC_ADDR_MODE_MASK) == 0x30) {
    memcpy(source_lladdr, &linkaddr_node_addr, sizeof(linkaddr_t));
    return true;
  }

  uint8_t src_addr_offset = SRC_ADDR_OFFSET;

  // Has inline hop limit? This moves the source addr one byte
  if(((*data) & HOP_LIMIT_MASK) == 0) {
    src_addr_offset++;
//    LOG_DBG("inline hoplimit\n");
  }

  linkaddr_t* fetched_source_address = (linkaddr_t*)(data + src_addr_offset);

  // Create an ipaddr and fill the interface id from the buf
  uip_ipaddr_t ipaddr = {0};
  memcpy(ipaddr.u8 + 8, fetched_source_address->u8, LINKADDR_SIZE);

  // Use ds6 to properly decode lladdr from IP.
  uip_ds6_set_lladdr_from_iid((uip_lladdr_t*) source_lladdr, &ipaddr);

  // This may be called by TSCH
//  LOG_DBG("Found node ");
//  LOG_DBG_LLADDR(source_lladdr);
//  LOG_DBG_("\n");

  return true;
}

/*---------------------------------------------------------------------------*/
bool
layered_get_flow_address_for_packet(uint16_t frame_type, const uint8_t* data,
                                    uint16_t data_len,
                                    linkaddr_t* flow_address) {

  // TODO might be that this can always be found in PACKETBUF_ATTR_PACKET_TYPE
  packet_type_t packet_type = packet_type_get(frame_type, data, data_len);

  switch(packet_type) {
    case PACKET_TYPE_APP:
      if(!find_source_address(data, data_len, flow_address)) {
         // Unable to find the source address, this should not happen
        LOG_ERR("Panic!\n");
        return false;
      }
      // Convert the source address into its flow address
      tsch_schedule_convert_to_flow_address(flow_address);
//      LOG_DBG("Flow packet\n");
      return true;
    case PACKET_TYPE_BEACON:
    case PACKET_TYPE_RPL:
    case PACKET_TYPE_KEEPALIVE:
    default:
//      LOG_DBG("Not flow packet\n");
      return false;
  }
}

/*---------------------------------------------------------------------------*/

static bool
is_root(void) {
  // Note that this might not show correct until after app. has started
  return NETSTACK_ROUTING.node_is_root();
}

#if !LAYERED_STATEFUL
static bool cell_already_there(uint16_t timeslot, uint16_t channel,
                               uint8_t link_options, enum link_type link_type) {

  struct tsch_link * curr = tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channel);

  if(curr != NULL &&
      curr->channel_offset == channel &&
      curr->link_options == link_options &&
      curr->link_type == link_type) {
    return true;
  }

  return false;
}

// Workaround to remove any existing cells
static void remove_other_cells_in_timeslot(uint16_t timeslot, uint16_t channel) {
  for(uint16_t i = 0; i < NUM_CHANNELS; i++) {
    if(channels[i] != channel) {
      struct tsch_link* existing_link =
          tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channels[i]);

      if(existing_link != NULL) {
        tsch_schedule_remove_link(sf_layered, existing_link);
#if LAYERED_STATS
        stats_deactivate_link(timeslot, channels[i]);
#endif
        LOG_INFO("Removed existing cell %u/%u\n", timeslot, channels[i]);
      }
    }
  }
}
#endif

static void
schedule_upwards_tx_cell(
    const linkaddr_t *linkaddr, uint8_t layer, uint8_t depth, bool remove) {
  uint8_t link_options = LINK_OPTION_TX;
  uint16_t timeslot = calculate_layered_timeslot(linkaddr, layer);
  uint16_t channel = calculate_channel(depth);

  if(timeslot == 0xffff) {
    return;
  }

  rpl_dag_t* rpl_dag = rpl_get_any_dag();
  const linkaddr_t* parent_linkaddr =
      rpl_get_parent_lladdr(rpl_dag->preferred_parent);

#if LAYERED_STATS && !LAYERED_STATEFUL
  if(remove) {
    stats_deactivate_link(timeslot, channel);
  }
  else {
    stats_add_link(timeslot, channel, link_options);
  }
#endif

  if(remove) {
    LOG_INFO("Removing upwards TX cell %u/%u to ", timeslot, channel);
    LOG_INFO_LLADDR(parent_linkaddr);
    LOG_INFO_(" for traffic from ");
    LOG_INFO_LLADDR(linkaddr);
    LOG_INFO_("\n");

#if LAYERED_STATEFUL
    remove_link(timeslot, channel);
#else
    struct tsch_link* link_to_remove =
        tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channel);
    // TODO add error-handling
    if(!tsch_schedule_remove_link(sf_layered, link_to_remove)) {
      LOG_WARN("Remove link failed\n");
    }
#endif
  }
  else {
#if LAYERED_STATEFUL
    LOG_INFO("Adding upwards TX cell %u/%u to ", timeslot, channel);
         LOG_INFO_LLADDR(parent_linkaddr);
         LOG_INFO_(" for traffic from ");
         LOG_INFO_LLADDR(linkaddr);
         LOG_INFO_("\n");
    add_link(timeslot, channel, link_options,
             LINK_TYPE_NORMAL, linkaddr, true);
#else
    if(!cell_already_there(timeslot, channel, link_options, LINK_TYPE_NORMAL)) {
      LOG_INFO("Adding upwards TX cell %u/%u to ", timeslot, channel);
      LOG_INFO_LLADDR(parent_linkaddr);
      LOG_INFO_(" for traffic from ");
      LOG_INFO_LLADDR(linkaddr);
      LOG_INFO_("\n");

      // Workaround to remove any existing cells
      remove_other_cells_in_timeslot(timeslot, channel);
      if(!tsch_schedule_add_link(sf_layered, link_options, LINK_TYPE_NORMAL,
                                 linkaddr, timeslot, channel, 1, true)) {
        LOG_WARN("Add link failed\n");
      }
    }
#endif /* LAYERED_STATEFUL */
  }
}

static void
schedule_upwards_rx_cell(
    const linkaddr_t *linkaddr, uint8_t layer, uint8_t depth, bool remove) {
  uint8_t link_options = LINK_OPTION_RX;
  uint16_t timeslot = calculate_layered_timeslot(linkaddr, layer);
  uint16_t channel = calculate_channel(depth);

  // Don't add stats for RX cells
//#if LAYERED_STATS
//  stats_add_link(timeslot, channel);
//#endif

  // We set broadcast as the "destination address",
  // but since this is a RX cell the value is probably ignored TODO
  if(remove) {
    LOG_INFO("Removing upwards RX cell %u/%u for traffic from ",
             timeslot, channel);
    LOG_INFO_LLADDR(linkaddr);
    LOG_INFO_("\n");

#if LAYERED_STATEFUL
    remove_link(timeslot, channel);
#else
    struct tsch_link* link_to_remove =
            tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channel);
    if(!tsch_schedule_remove_link(sf_layered, link_to_remove)) {
      LOG_WARN("Remove link failed\n");
    }
#endif
  }
  else {
#if LAYERED_STATEFUL
    LOG_INFO("Adding upwards RX cell %u/%u for traffic from ",
             timeslot, channel);
    LOG_INFO_LLADDR(linkaddr);
    LOG_INFO_("\n");
    add_link(timeslot, channel, link_options,
             LINK_TYPE_NORMAL, &tsch_broadcast_address, false);
#else
    if(!cell_already_there(timeslot, channel, link_options, LINK_TYPE_NORMAL)) {
      LOG_INFO("Adding upwards RX cell %u/%u for traffic from ",
               timeslot, channel);
      LOG_INFO_LLADDR(linkaddr);
      LOG_INFO_("\n");

      remove_other_cells_in_timeslot(timeslot, channel);

      // We do not care about RX cells being connected to flow
      if(!tsch_schedule_add_link(sf_layered, link_options, LINK_TYPE_NORMAL,
                                 &tsch_broadcast_address, timeslot, channel,
                                 1, false)) {
        LOG_WARN("Add link failed\n");
      }
    }
#endif /* LAYERED_STATEFUL */
  }
}

static void
schedule_downwards_tx_cell(
    const linkaddr_t *linkaddr, uint8_t layer, uint8_t depth, bool remove) {
  uint8_t link_options = LINK_OPTION_TX;
  uint16_t timeslot = calculate_layered_timeslot(linkaddr, layer);
  uint16_t channel = calculate_channel(depth);

#if LAYERED_STATS && !LAYERED_STATEFUL
  if(remove) {
    stats_deactivate_link(timeslot, channel);
  }
  else {
    stats_add_link(timeslot, channel, link_options);
  }
#endif

  // Currently limit to beacons
  if(remove) {
    LOG_INFO("Removing downwards TX cell %u/%u\n", timeslot, channel);
#if LAYERED_STATEFUL
    remove_link(timeslot, channel);
#else
    struct tsch_link* link_to_remove =
        tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channel);
    if(!tsch_schedule_remove_link(sf_layered, link_to_remove)) {
      LOG_WARN("Remove link failed\n");
    }
#endif
  }
  else {
#if LAYERED_STATEFUL
    LOG_INFO("Adding downwards TX cell %u/%u\n", timeslot, channel);
    add_link(timeslot, channel, link_options,
             LINK_TYPE_ADVERTISING_ONLY, &tsch_broadcast_address, false);
#else
    if(!cell_already_there(timeslot, channel, link_options, LINK_TYPE_ADVERTISING_ONLY)) {
      LOG_INFO("Adding downwards TX cell %u/%u\n", timeslot, channel);

      remove_other_cells_in_timeslot(timeslot, channel);

      if(!tsch_schedule_add_link(sf_layered, link_options,
                                 LINK_TYPE_ADVERTISING_ONLY,
                                 &tsch_broadcast_address, timeslot, channel,
                                 1, false)) {
        LOG_WARN("Add link failed\n");
      }
    }
#endif /* LAYERED_STATEFUL */
  }
}

static void
schedule_downwards_rx_cell(
    const linkaddr_t *linkaddr, uint8_t layer, uint8_t depth, bool remove) {
  uint8_t link_options = LINK_OPTION_RX;
  uint16_t timeslot = calculate_layered_timeslot(linkaddr, layer);
  uint16_t channel = calculate_channel(depth);

  // Don't add stats for RX cells
//#if LAYERED_STATS
//  stats_add_link(timeslot, channel);
//#endif


  // Currently limited to beacons
  if(remove) {
    LOG_INFO("Removing downwards RX cell %u/%u\n", timeslot, channel);
#if LAYERED_STATEFUL
    remove_link(timeslot, channel);
#else
    struct tsch_link* link_to_remove =
        tsch_schedule_get_link_by_timeslot(sf_layered, timeslot, channel);
    if(!tsch_schedule_remove_link(sf_layered, link_to_remove)) {
      LOG_WARN("Remove link failed\n");
    }
#endif
  }
  else {
#if LAYERED_STATEFUL
    LOG_INFO("Adding downwards RX cell %u/%u\n", timeslot, channel);
    add_link(timeslot, channel, link_options,
             LINK_TYPE_ADVERTISING_ONLY, &tsch_broadcast_address, false);
#else
    if(!cell_already_there(timeslot, channel, link_options, LINK_TYPE_ADVERTISING_ONLY)) {
      LOG_INFO("Adding downwards RX cell %u/%u\n", timeslot, channel);

      remove_other_cells_in_timeslot(timeslot, channel);

      if(!tsch_schedule_add_link(sf_layered, link_options,
                                 LINK_TYPE_ADVERTISING_ONLY,
                                 &tsch_broadcast_address, timeslot, channel,
                                 1, false)) {
        LOG_WARN("Add link failed\n");
      }
    }
#endif /* LAYERED_STATEFUL */
  }
}

static void schedule_common_cells(void) {
  // Add common cells used for RPL and downward application traffic
  for(uint16_t i = FIRST_COMMON_SLOT;
      i < LAYERED_SF_LEN;
      i += COMMON_SLOT_SPACING) {

    uint16_t timeslot = i;
    uint16_t channel = COMMON_CELL_CHANNEL;
    uint8_t options = COMMON_SLOT_OPTIONS;

    LOG_INFO("Adding common cell %u/%u\n", timeslot, channel);

#if LAYERED_STATEFUL
    add_link(timeslot, channel, options,
             LINK_TYPE_NORMAL, &tsch_broadcast_address, false);
#else
#if LAYERED_STATS
    stats_add_link(timeslot, channel, options);
#endif
    if(!tsch_schedule_add_link(sf_layered, options, LINK_TYPE_NORMAL,
                           &tsch_broadcast_address, i, channel, 1, false)) {
      LOG_ERR("Add common cells failed!\n");
    }
#endif /* LAYERED_STATEFUL */
  }
#if LAYERED_STATEFUL
  sync_links_with_schedule();
#endif
}

// TODO NOTE! This does not use same notation as in paper,
// here we have the most lowered-number layer closest to the sink
static uint8_t calculate_layer(uint16_t depth) {
  // Treat the root as on layer 1
  if(depth == 0) {
    depth = 1;
  }

  // For arithmetic simplicity
  depth--;

  // Calc layer (0 or 1)
  uint8_t layer = depth % LAYERED_NUM_LAYERS;

  // And back to layer 1 and 2
  layer++;

  return layer;
}

static void
add_cells(const linkaddr_t *linkaddr, layered_status_t* status, bool default_route) {
  if(linkaddr == NULL) {
    LOG_ERR("linkaddr NULL!\n");
    return;
  }

  LOG_INFO("Scheduling cells (node/child depth %u/%u, layer %u/%u)\n",
           status->node_depth, status->child_depth, status->node_layer, status->child_layer);

  // Receive traffic forwarded by our child
  // The originating node (could be the child) is indicated in linkaddr, and
  // The layer and depth would be the one below our own
  // This cell is not necessary if this was the default-route, i.e.
  // the originating node would be ourself
  if(!default_route) {
    schedule_upwards_rx_cell(linkaddr, status->child_layer, status->child_depth, false);
  }

  // Forward upward traffic originated at the node indicated by the linkaddr
  // The layer is our own
  // Not needed if we are root
  if(!is_root()) {
    // If it was a default route we are the originating node,
    // use our address and depth
    if(default_route) {
      schedule_upwards_tx_cell(
          &linkaddr_node_addr, status->node_layer, status->node_depth, false);
    }
    else {
      schedule_upwards_tx_cell(linkaddr, status->node_layer, status->node_depth, false);
    }
  }

  // Send beacons to our childs
  // Use our own addr, but at the layer and depth below us
  if(default_route) {
    schedule_downwards_tx_cell(&linkaddr_node_addr, status->child_layer, status->child_depth, false);
  }

  // Receive beacons from parent
  // This should follow our parent address, yet our layer and depth
  // It is not necessary if we are root
  if(default_route && !is_root()) {
    schedule_downwards_rx_cell(linkaddr, status->node_layer, status->node_depth, false);
  }
#if LAYERED_STATEFUL
  sync_links_with_schedule();
#endif
}

static void
remove_cells(const linkaddr_t *linkaddr, layered_status_t* status, bool default_route) {
  if(linkaddr == NULL) {
    LOG_ERR("linkaddr NULL!\n");
    return;
  }

  LOG_INFO("Removing cells (node/child depth %u/%u, layer %u/%u)\n",
           status->node_depth, status->child_depth, status->node_layer, status->child_layer);

  // We will no longer receive traffic forwarded by our child
  // The originating node (could be the child) is indicated in linkaddr, and
  // The layer and depth would be the one below our own
  // This cell is not necessary if this was the default-route, i.e.
  // the originating node would be ourself
  if(!default_route) {
    schedule_upwards_rx_cell(linkaddr, status->child_layer, status->child_depth, true);
  }

  // No longer forward upward traffic originated at the node indicated by linkaddr
  // The layer is our own
  // Not needed if we are root
  if(!is_root()) {
    // If it was a default route we are the originating node,
    // use our address and depth
    if(default_route) {
      schedule_upwards_tx_cell(
          &linkaddr_node_addr, status->node_layer, status->node_depth, true);
    }
    else {
      schedule_upwards_tx_cell(linkaddr, status->node_layer, status->node_depth, true);
    }
  }

  // No longer send beacons to our childs since we might have moved
  // Use our own addr, but at the layer and depth below us
  // This is not necessary if we have no childs (except if we are root)
  if(default_route) {
    schedule_downwards_tx_cell(
        &linkaddr_node_addr, status->child_layer, status->child_depth, true);
  }

  // No longer receive beacons from this parent
  // This should follow our parent address, yet our layer and depth
  // It is not necessary if we are root
  if(default_route && !is_root()) {
    schedule_downwards_rx_cell(linkaddr, status->node_layer, status->node_depth, true);
  }
#if LAYERED_STATEFUL
  sync_links_with_schedule();
#endif
}

static void update_current_status(uint16_t node_new_depth) {
  if(node_new_depth != current_status.node_depth) {
    LOG_INFO("Node switched depth from %u to %u\n",
             current_status.node_depth, node_new_depth);
    current_status.node_depth = node_new_depth;
  }

  uint8_t node_new_layer = calculate_layer(current_status.node_depth);
  if(node_new_layer != current_status.node_layer) {
    LOG_INFO("Node switched layer from %u to %u\n",
             current_status.node_layer, node_new_layer);
    current_status.node_layer = node_new_layer;
  }

  uint8_t child_new_depth = node_new_depth + 1;
  if(child_new_depth != current_status.child_depth) {
    LOG_INFO("Child switched depth from %u to %u\n",
             current_status.child_depth, child_new_depth);
    current_status.child_depth = child_new_depth;
  }

  uint8_t child_new_layer = calculate_layer(current_status.child_depth);
  if(child_new_layer != current_status.child_layer) {
    LOG_INFO("Child switched layer from %u to %u\n",
             current_status.child_layer, child_new_layer);
    current_status.child_layer = child_new_layer;
  }
}

// If exploring power optimizations
//#if LAYERED_STATEFUL
//static void remove_all_links(void) {
//  LOG_WARN("Removing all links\n");
//  for(int i = 0; i < MAX_NUM_LINKS; i++) {
//    if(layered_links[i].occupied &&
//        layered_links[i].options != COMMON_SLOT_OPTIONS &&
//        (layered_links[i].scheduled || layered_links[i].should_be_scheduled)) {
//      layered_links[i].should_be_scheduled = false;
//    }
//  }
//
//  sync_links_with_schedule();
//}
//#endif

static void
route_callback(int event,
               const uip_ipaddr_t *route,
               const uip_ipaddr_t *next_hop,
               int num_routes,
               bool route_update) {

  bool route_added =
      (event == UIP_DS6_NOTIFICATION_DEFRT_ADD ||
          event == UIP_DS6_NOTIFICATION_ROUTE_ADD);
  static linkaddr_t old_def_route = {{0}};

#if LAYERED_STATEFUL
  // Utilize the periodic refreshing of routes to check our sync
  // TODO evaluate if frequent enough
  if(!schedule_in_sync()) {
    LOG_WARN("Schedule not in sync\n");
    sync_links_with_schedule();
  }
#endif

  // Fetch the route link-layer address by dissecting the IP
  linkaddr_t route_lladdr = {{0}};
  uip_ds6_set_lladdr_from_iid((uip_lladdr_t*)&route_lladdr, route);

  rpl_dag_t* rpl_dag = rpl_get_any_dag();
  if(rpl_dag == NULL) {
    LOG_ERR("No dag!\n");
    return;
  }

  layered_status_t previous_status = current_status;

  // Fetch depth from dag
  uint16_t node_new_depth = rpl_dag->depth;
  if(node_new_depth == 0xffff) {
    LOG_ERR("New depth invalid! %u\n", route_added);
    // Our depth is invalid, probably we have lost all parents. Do not
    // add cells for new routes as we don't know the depth, but allow removal of old
#if LAYERED_STATEFUL
    //remove_all_links(); // TODO investigate for power optimization
#endif
    if(route_added) {
      return;
    }
  }
  else {
    // Valid depth, update our status
    update_current_status(node_new_depth);
  }

  if(event == UIP_DS6_NOTIFICATION_DEFRT_ADD) {
    LOG_INFO("Added default route to ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_6ADDR(next_hop);
    LOG_INFO_("\n");
    // Ignore refreshes of the default route where the depth is not changed
    if(!(route_update &&
        previous_status.node_depth == current_status.node_depth)) {

      // This is either a completely new parent, or update (or adding) on our
      // existing parent which have moved to a new depth. Now we must handle
      // the RX beacon.
      // For the first case, the cell was removed by the remove-route callback
      // For the second case, we remove the cell here
      if(!is_root() &&
          previous_status.node_depth != 0xffff &&
          linkaddr_cmp(&old_def_route, &route_lladdr)) {
        schedule_downwards_rx_cell(&route_lladdr, previous_status.node_layer,
                                   previous_status.node_depth, true);
      }

      add_cells(&route_lladdr, &current_status, true);
      linkaddr_copy(&old_def_route, &route_lladdr);
    }
  }
  else if(event == UIP_DS6_NOTIFICATION_DEFRT_RM) {
    LOG_INFO("Removed default route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_6ADDR(next_hop);
    LOG_INFO_("\n");
    linkaddr_copy(&old_def_route, &linkaddr_null);
#if LAYERED_STATEFUL
//    remove_all_links(); // TODO investigate for power optimization
    remove_cells(&route_lladdr, &previous_status, true);
#else
    remove_cells(&route_lladdr, &previous_status, true);
#endif
  }
  else if(event == UIP_DS6_NOTIFICATION_ROUTE_ADD) {
    LOG_INFO("Added route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_6ADDR(next_hop);
    LOG_INFO_("\n");
    add_cells(&route_lladdr, &current_status, false);
  }
  else if(event == UIP_DS6_NOTIFICATION_ROUTE_RM) {
    LOG_INFO("Removed route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_6ADDR(next_hop);
    LOG_INFO_("\n");
    remove_cells(&route_lladdr, &current_status, false);
  }
}

/*---------------------------------------------------------------------------*/
static void
init(uint16_t sf_handle)
{
  // Register for route changes
  static struct uip_ds6_notification n;
  uip_ds6_notification_add(&n, route_callback);
  LOG_INFO("Registered for route changes\n");

  slotframe_handle = sf_handle;

  /* Slotframe for unicast transmissions */
  sf_layered = tsch_schedule_add_slotframe(
      slotframe_handle, LAYERED_SF_LEN);

  schedule_common_cells();

  // If we are root we already know our depth,
  // so we can add the downward beacon cell
  if(is_root()) {
    LOG_INFO("Adding downward cell for root\n");
    current_status.node_depth = 0;
    current_status.child_depth = 1;
    current_status.node_layer = calculate_layer(current_status.node_depth);
    current_status.child_layer = calculate_layer(current_status.child_depth);
    add_cells(&linkaddr_node_addr, &current_status, true);
  }
}
/*---------------------------------------------------------------------------*/
struct layered_rule layered_multi_channel = {
  init,
  NULL,
  NULL,
  NULL,
  NULL,
  "layered multi-channel",
};
