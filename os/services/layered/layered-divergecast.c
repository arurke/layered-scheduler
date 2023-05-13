#include "contiki.h"
#include "layered.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/routing/routing.h"
#include "sys/node-id.h"
#include "rpl.h"
#include "rpl-private.h"
#include "uip-icmp6.h"
#include "lib/random.h"
#include "packet-type.h"
#include "timer.h"
#include "ctimer.h"
#include <inttypes.h>

/*---------------------------------------------------------------------------*/

#include "sys/log.h"
#define LOG_MODULE "Layered"
#define LOG_LEVEL   LOG_LEVEL_LAYERED

/*---------------------------------------------------------------------------*/

// Interval for periodic check of schedule sync (and link timeouts)
#define SCHEDULE_PERIODIC_CHECK_INTERVAL (1 * CLOCK_SECOND)

// Time to wait after route changes before adding new TX links, this because
// packets can be queued towards the old parent while we switch to the new.
// This causes our judgement on the packet direction to be wrong.
#define ROUTE_CHANGE_WAIT_TIMER  (LAYERED_ROUTE_CHANGE_WAIT_SEC * CLOCK_SECOND)

#define PARENT_CHANGE_WAIT_TIMER (LAYERED_PARENT_CHANGE_WAIT_SEC * CLOCK_SECOND)

#define NEW_NEIGHBOR_RX_WAIT_TIMER PARENT_CHANGE_WAIT_TIMER

// Run unit-tests
#define RUN_TESTS        0

// The current RPL preferred parent's link-layer address
// Used to judge if a sent packet went upwards or downwards
static linkaddr_t parent_linkaddr;

/* A net-layer sniffer for packets sent and received */
static void layered_packet_received(void);
static void layered_packet_sent(int mac_status);
NETSTACK_SNIFFER(layered_sniffer, layered_packet_received, layered_packet_sent);

static void add_link(uint16_t timeslot, uint16_t channel,
                     uint8_t options, enum link_type link_type,
                     const linkaddr_t* address, const linkaddr_t* dest_address,
                     bool direction_upwards,
                     bool is_flow, const linkaddr_t* learned_via);

/*---------------------------------------------------------------------------*/

typedef struct {
  uint16_t node_depth;
  uint8_t node_layer;
  uint16_t child_depth;
  uint8_t child_layer;
} layered_status_t;

static uint16_t slotframe_handle = 0;
static struct tsch_slotframe *sf_layered;
static struct ctimer ct_periodic;
struct timer route_change_timer;
struct timer parent_change_timer;
struct timer new_neighbor_rx_timer;

#define COMMON_CELL_CHANNEL         1
#define NUM_CHANNELS                LAYERED_NUM_CHANNELS
#define NUM_CHANNELS_PER_DIRECTION  (LAYERED_NUM_CHANNELS / 2)
#define CHANNELS                    LAYERED_CHANNELS

// Avoid channel offset 0 due to stats not supporting it.
static uint8_t channels[NUM_CHANNELS] = CHANNELS;

#define FIRST_COMMON_SLOT         (COMMON_SLOT_SPACING - 1)
#define COMMON_SLOT_OPTIONS       (LINK_OPTION_RX | LINK_OPTION_TX | LINK_OPTION_SHARED)

#if RUN_TESTS
static int tests(void);
#endif

uint16_t last_depth = 0xffff;

typedef struct {
  bool occupied;
  uint16_t timeslot;
  uint16_t channel;
  uint8_t options;
  enum link_type link_type;
  linkaddr_t address;
  linkaddr_t dest_address;
  bool direction_upwards;
  bool is_flow;
  bool should_be_scheduled;
  bool scheduled;
  struct timer timeout_timer;
  linkaddr_t learned_via;
#if LAYERED_STATS
  uint32_t tx_attempts;
  uint32_t no_ok_mac;
#endif
} layered_link_t;

// This also includes RX links
#define MAX_NUM_LINKS   100

static layered_link_t layered_links[MAX_NUM_LINKS] = {{0}};

static bool schedule_in_sync(void);
static void sync_links_with_schedule(void);
static bool first_rx_learned_from_this_neighbor(const linkaddr_t* learned_via);

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
  //tsch_schedule_print(); // In simulator, excessive printing can be bugging

  static int test = 0;
  if(test != 3) {
    test++;
    return;
  }
  test = 0;

  LOG_INFO("Printing stats:\n");
  int i = 0;
  uint8_t num_links = 0;
  for(i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied) {

      num_links++;

      // Don't print if not scheduled and no TX attempts
      if(!layered_links[i].scheduled &&
          layered_links[i].tx_attempts == 0 &&
          layered_links[i].no_ok_mac == 0) {
        continue;
      }

      if(layered_links[i].options & LINK_OPTION_SHARED) {
        LOG_INFO("BC      : ");
      }
      else {
        LOG_INFO("UC-%s-%s: ",
                 layered_links[i].options & LINK_OPTION_TX ? "tx" : "rx",
                 layered_links[i].direction_upwards ? "up" : "do");
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
}
#endif /* LAYERED_STATS */

/*---------------------------------------------------------------------------*/

static uint16_t
get_current_depth(void) {
  rpl_dag_t* rpl_dag = rpl_get_any_dag();
  if(rpl_dag == NULL) {
    LOG_ERR("No DAG when fetching depth\n");
    return 0xffff;
  }
  return rpl_dag->depth;
}

/*---------------------------------------------------------------------------*/
static uint16_t
get_node_timeslot(const linkaddr_t *addr)
{
  if(addr != NULL && LAYERED_MAX_NUM_NODES > 0) {
    // +1 as we assume the last node will ID equal to the max num nodes
    // see also 0-index comment in calculate_timeslot()
//    return LAYERED_LINKADDR_HASH(addr) % (LAYERED_MAX_NUM_NODES + 1);

    // +1 as we assume the last node will ID equal to the max num nodes
    // -1 as we assume node IDs starts at 1.
    return (LAYERED_LINKADDR_HASH(addr) % (LAYERED_MAX_NUM_NODES + 1)) - 1;
  } else {
    return 0xffff;
  }
}

/*---------------------------------------------------------------------------*/
// Assumes layers starts at 1
static uint16_t
calculate_timeslot(const linkaddr_t *linkaddr, uint8_t layer) {
  // Hash of node id
  uint16_t timeslot = get_node_timeslot(linkaddr);

  if(timeslot == 0xffff) {
    LOG_ERR("PANIC: Unable to calculate timeslot for layer %u, addr. ", layer);
    LOG_ERR_LLADDR(linkaddr);
    LOG_ERR_("\n");
    return 0xffff;
  }

  // Shift right into correct layer
  timeslot += (layer - 1) * LAYERED_MAX_NUM_NODES;

  // Shift to accommodate any common slots. -1 due to ts being 0-index
  uint16_t num_common_slots_so_far = timeslot / (COMMON_SLOT_SPACING - 1);
  timeslot += num_common_slots_so_far;

  return timeslot;
}

/*---------------------------------------------------------------------------*/
static uint16_t
calculate_channel(uint16_t depth, bool direction_upwards)
{
  uint16_t channel = (depth / LAYERED_NUM_LAYERS) % NUM_CHANNELS_PER_DIRECTION;

  // If downward traffic, use the second half of the channels
  if(!direction_upwards) {
    channel += NUM_CHANNELS_PER_DIRECTION;
  }

  // Fetch channel offset
  channel = channels[channel];

  return channel;
}

/*---------------------------------------------------------------------------*/

static uint8_t
calculate_layer(uint16_t depth) {
  // Calc layer (0 or 1)
  // +1 ensures layering matching the paper (depth 0 -> rightmost layer)
  uint8_t layer = (depth + 1) % LAYERED_NUM_LAYERS;

  // And back to layer 1 and 2
  layer++;

  return layer;
}

/*---------------------------------------------------------------------------*/
static bool
is_root(void) {
  // Note that this might not show correct until after app. has started
  return NETSTACK_ROUTING.node_is_root();
}

/*---------------------------------------------------------------------------*/

static void
add_flow_rx_cells(const linkaddr_t* source_address,
                  const linkaddr_t* dest_address,
                  const linkaddr_t* learned_via,
                  bool direction_upwards, uint16_t depth) {
  if(depth == 0xffff) {
    LOG_WARN("Not adding RX cells since depth is 0xffff\n");
    return;
  }
  if(linkaddr_cmp(&parent_linkaddr, &linkaddr_null) && !direction_upwards) {
    LOG_INFO("Not adding downwards RX cells since we lost parent\n");
    return;
  }

  // Adjust the depth according to direction
  if(direction_upwards) {
    depth++;
  }
  else {
    if(depth == 0) {
      LOG_ERR("PANIC: Trying to RX above the root\n");
      return;
    }
    depth--;
  }

  uint8_t link_options = LINK_OPTION_RX;
  uint16_t timeslot = calculate_timeslot(source_address,
                                         calculate_layer(depth));
  uint16_t channel = calculate_channel(depth, direction_upwards);

  // Check if we have any existing RX cells from this neighbor
  // If not it may be a new neighbor and we should halt e.g.
  // the inconsistency mechanism so that we can receive updated DIO.
  if(first_rx_learned_from_this_neighbor(learned_via)) {
    timer_set(&new_neighbor_rx_timer, NEW_NEIGHBOR_RX_WAIT_TIMER);
    LOG_DBG("First RX link for this neighbor\n");
  }

  LOG_INFO("Adding %s RX cell %u/%u depth %u for traffic from ",
           direction_upwards ? "upwards" : "downwards",
           timeslot, channel, depth);
  LOG_INFO_LLADDR(source_address);
  LOG_INFO_("\n");
  LOG_DBG("Destination ");
  LOG_DBG_LLADDR(dest_address);
  LOG_DBG_("\n");
  LOG_DBG("Learned via ");
  LOG_DBG_LLADDR(learned_via);
  LOG_DBG_("\n");
  add_link(timeslot, channel, link_options,
           LINK_TYPE_NORMAL, source_address, dest_address,
           direction_upwards, true, learned_via);
}

/*---------------------------------------------------------------------------*/
static void
add_flow_tx_cells(const linkaddr_t* source_address,
                  const linkaddr_t* dest_address,
                  const linkaddr_t* learned_via,
                  bool direction_upwards) {
  uint16_t depth = get_current_depth();
  if(depth == 0xffff) {
    LOG_WARN("Not adding TX cells since depth is 0xffff\n");
    return;
  }
  if(linkaddr_cmp(&parent_linkaddr, &linkaddr_null) && direction_upwards) {
    LOG_INFO("Not adding upwards TX cells since we lost parent\n");
    return;
  }

  uint16_t timeslot =
      calculate_timeslot(source_address, calculate_layer(depth));
  uint16_t channel = calculate_channel(depth, direction_upwards);
  uint8_t link_options = LINK_OPTION_TX;

  LOG_INFO("Adding %s TX cell %u/%u depth %u for traffic from ",
           direction_upwards ? "upwards" : "downwards",
           timeslot, channel, depth);
  LOG_INFO_LLADDR(source_address);
  LOG_INFO_("\n");
  LOG_DBG("Destination ");
  LOG_DBG_LLADDR(dest_address);
  LOG_DBG_("\n");
  LOG_DBG("Learned via ");
  LOG_DBG_LLADDR(learned_via);
  LOG_DBG_("\n");
  add_link(timeslot, channel, link_options,
           LINK_TYPE_NORMAL, source_address, dest_address,
           direction_upwards, true, learned_via);
}

/*---------------------------------------------------------------------------*/

void
link_print(layered_link_t* link) {
  LOG_WARN("Link: %u/%u options: %d, type: %d, dir: %s, is_flow: %d\n",
           link->timeslot, link->channel, link->options, link->link_type,
           link->direction_upwards ? "upwards" : "downwards", link->is_flow);
}

static bool
link_is_enabled(const layered_link_t* link) {
  return link->scheduled || link->should_be_scheduled;
}


static bool
first_rx_learned_from_this_neighbor(const linkaddr_t* learned_via) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        link_is_enabled(&layered_links[i]) &&
        (linkaddr_cmp(&(layered_links[i].learned_via), learned_via)) &&
        layered_links[i].options == LINK_OPTION_RX) {
      return true;
    }
  }
  return false;
}

// Returns the first enabled link with the given timeslot
static layered_link_t*
get_enabled_link_in_timeslot(uint16_t timeslot) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].timeslot == timeslot &&
        link_is_enabled(&layered_links[i])) {
      return &layered_links[i];
    }
  }
  return NULL;
}

static layered_link_t*
get_enabled_link_by_properties(
    const linkaddr_t* source_address,
    const linkaddr_t* dest_address,
    const linkaddr_t* learned_via,
    uint8_t options) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        link_is_enabled(&layered_links[i]) &&
        (linkaddr_cmp(&(layered_links[i].address), source_address)) &&
        (linkaddr_cmp(&(layered_links[i].dest_address), dest_address)) &&
        (linkaddr_cmp(&(layered_links[i].learned_via), learned_via)) &&
        layered_links[i].options == options) {
      return &layered_links[i];
    }
  }
  return NULL;
}

static layered_link_t*
get_enabled_link_by_address_options(const linkaddr_t* address,
                                    uint8_t options) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        link_is_enabled(&layered_links[i]) &&
        (linkaddr_cmp(&(layered_links[i].address), address)) &&
        layered_links[i].options == options) {
      return &layered_links[i];
    }
  }
  return NULL;
}

static bool
flow_has_link(const linkaddr_t* source_address, const linkaddr_t* dest_address,
              const linkaddr_t* learned_via, uint8_t options) {
  return
      get_enabled_link_by_properties(
          source_address, dest_address, learned_via, options) != NULL;
}

static void
reset_link_timeout(layered_link_t* link) {
  if(link == NULL) {
    LOG_DBG("PANIC\n");
  }
  if(!link->is_flow) {
    return;
  }

  uint32_t timeout = LAYERED_LINK_TIMEOUT_SEC * CLOCK_SECOND;

  timer_set(&(link->timeout_timer), timeout);
  LOG_DBG("Resetting %u/%u link timeout for ", link->timeslot, link->channel);
  LOG_DBG_LLADDR(&link->address);
  LOG_DBG_("\n");
}

static bool
reset_link_timeout_by_properties(
    const linkaddr_t* source_addr,
    const linkaddr_t* dest_addr,
    const linkaddr_t* learned_via,
    uint8_t options) {
  layered_link_t* link =
      get_enabled_link_by_properties(
          source_addr, dest_addr, learned_via, options);
  if(link == NULL) {
    LOG_ERR("Link not found when resetting\n");
    return false;
  }

  reset_link_timeout(link);
  return true;
}

static void
check_link_timeouts(void) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].scheduled &&
        layered_links[i].should_be_scheduled &&
        layered_links[i].is_flow &&
        timer_expired(&(layered_links[i].timeout_timer))) {
      layered_links[i].should_be_scheduled = false;
      LOG_WARN("Timed out %s link %u/%u for ",
               layered_links[i].options == LINK_OPTION_TX ? "TX" : "RX",
               layered_links[i].timeslot, layered_links[i].channel);
      LOG_WARN_LLADDR(&(layered_links[i].address));
      LOG_WARN_("\n");
    }
  }
}

// Returns link matching the timeslot/channel
static layered_link_t*
get_link(uint16_t timeslot, uint16_t channel) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].timeslot == timeslot &&
        layered_links[i].channel == channel) {
      return &layered_links[i];
    }
  }
  return NULL;
}

static uint8_t
get_available_index(void) {
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

static bool
schedule_in_sync(void) {
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].scheduled != layered_links[i].should_be_scheduled) {
      return false;
    }
  }
  return true;
}

static void
remove_link_by_ptr(layered_link_t* link) {
  LOG_DBG("Removing link %u/%u %s ", link->timeslot, link->channel,
          link->is_flow ? "for flow" : "to");
  LOG_DBG_LLADDR(&link->address);
  LOG_DBG_("\n");
  link->should_be_scheduled = false;
//  sync_links_with_schedule();
}

static void
remove_link(uint16_t timeslot, uint16_t channel) {
  layered_link_t* existing_link = get_link(timeslot, channel);
  if(existing_link == NULL) {
    LOG_WARN("Unable to remove non-existing link %u/%u\n", timeslot, channel);
    return;
  }
  else {
    existing_link->should_be_scheduled = false;
    LOG_DBG("Removing link %u/%u %s ",
            timeslot, channel, existing_link->is_flow ? "for flow" : "to");
    LOG_DBG_LLADDR(&existing_link->address);
    LOG_DBG_("\n");
  }

  sync_links_with_schedule();
}

static void
add_link_by_ptr(const layered_link_t* link) {
  add_link(
      link->timeslot, link->channel,
      link->options, link->link_type,
      &(link->address), &(link->dest_address),
      link->direction_upwards, link->is_flow,
      &(link->learned_via));
}

static layered_link_t last_rx_link_overwritten = {0};
static linkaddr_t last_rx_link_overwritten_trigger = {0};

static void
add_link(
    uint16_t timeslot, uint16_t channel,
    uint8_t options, enum link_type link_type,
    const linkaddr_t* address, const linkaddr_t* dest_address,
    bool direction_upwards, bool is_flow, const linkaddr_t* learned_via) {

  // TODO handle !is_flow + direction
  // This is common cells, leave all at false upwards for now
  if(timeslot == 0xffff || channel == 0xffff) {
    LOG_ERR("PANIC: Not adding link for %u/%u\n", timeslot, channel);
    return;
  }

  // Make sure we are operating on an up-to-date schedule
  sync_links_with_schedule();

  // Remove any existing cell in the same timeslot
  layered_link_t* existing_link_in_ts = get_enabled_link_in_timeslot(timeslot);
  if(existing_link_in_ts != NULL) {
    LOG_DBG("Enabled link already in TS %u, removing\n", timeslot);

    // Store this link and who caused the deletion in case we need to revert
    if(existing_link_in_ts->options == LINK_OPTION_RX) {
      last_rx_link_overwritten = *existing_link_in_ts;
      linkaddr_copy(&last_rx_link_overwritten_trigger, learned_via);
    }

    remove_link(existing_link_in_ts->timeslot, existing_link_in_ts->channel);
  }

  // Sanity check (should be only one cell scheduled in same TS)
  if(get_enabled_link_in_timeslot(timeslot) != NULL) {
    LOG_ERR("PANIC: Multiple cells scheduled in TS %u\n", timeslot);
  }

  // Add new link
  layered_link_t new_link =
    { .occupied = true,
      .timeslot = timeslot,
      .channel = channel,
      .options = options,
      .link_type = link_type,
      .is_flow = is_flow,
      .direction_upwards = direction_upwards,
      .should_be_scheduled = true,
      .scheduled = false,
      .timeout_timer = {0}
    };

  linkaddr_copy(&new_link.address, address);
  linkaddr_copy(&new_link.dest_address, dest_address);
  linkaddr_copy(&new_link.learned_via, learned_via);

  layered_link_t* existing_link = get_link(timeslot, channel);
  if(existing_link != NULL) {
    *existing_link = new_link;
  }
  else {
    uint8_t new_link_index = get_available_index();
    if(new_link_index > MAX_NUM_LINKS) {
      LOG_ERR("PANIC: No room for more links!\n");
      return;
    }
    else {
      layered_links[new_link_index] = new_link;
    }
  }

  LOG_DBG("Adding link %u/%u %s ",
          timeslot, channel, &new_link.is_flow ? "for flow" : "to");
  LOG_DBG_LLADDR(&new_link.address);
  LOG_DBG_("\n");
  sync_links_with_schedule();
}

static int index_for_last_rx_link_added = -1;

static void
sync_links_with_schedule(void) {
  check_link_timeouts();

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
          // Ad-hoc for when disabling a node
          if(!tsch_allow_association) {
            layered_links[i].scheduled = false;
          }
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
          reset_link_timeout(&layered_links[i]);
        }

        // Store index of scheduled RX link for consistency check
        if(layered_links[i].options == LINK_OPTION_RX) {
          index_for_last_rx_link_added = i;
        }

      }
    }
  }
}

/*---------------------------------------------------------------------------*/
static bool
packet_direction_is_upwards(
    bool was_tx, const linkaddr_t* sender,
    const linkaddr_t* receiver,
    const linkaddr_t* parent) {

  bool direction_upwards = true;
  if(was_tx) {
    if(linkaddr_cmp(receiver, parent)) {
      direction_upwards = true;
    }
    else {
      direction_upwards = false;
    }
  }
  else {
    if(linkaddr_cmp(sender, parent)) {
      direction_upwards = false;
    }
    else {
      direction_upwards = true;
    }
  }
  return direction_upwards;
}

static bool
packetbuf_direction_is_upwards(bool was_tx) {
  LOG_DBG("Checking direction for %s from ", was_tx ? "TX" : "RX");
  LOG_DBG_LLADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  LOG_DBG_(" to ");
  LOG_DBG_LLADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  LOG_DBG_("\n");

  LOG_DBG("Parent is ");
  if(!is_root()) {
    LOG_DBG_LLADDR(&parent_linkaddr);
    LOG_DBG_("\n");
  }
  else {
    LOG_DBG_("none (am root)\n");
  }

  bool direction_upwards = packet_direction_is_upwards(
      was_tx,
      packetbuf_addr(PACKETBUF_ADDR_SENDER),
      packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
      &parent_linkaddr);

  LOG_DBG("%s packet direction was %s\n",
          was_tx ? "TXed" : "RXed",
          direction_upwards ? "upwards" : "downwards");

  return direction_upwards;
}

/*---------------------------------------------------------------------------*/
static bool
is_app_packet_without_dedicated_link(linkaddr_t* source_address,
                                     linkaddr_t* dest_address,
                                     const linkaddr_t* from,
                                     bool was_ack) {
  // Was this app. packet?
  if(packet_type_set_from_packetbuf() == PACKET_TYPE_APP) {
    // Fetch source address and check if it is without dedicated link
    //LOG_DBG("Try to find source address\n");
    layered_get_source_address_for_app_packet_after_netstack_callbacks(
        was_ack, source_address);

    layered_get_dest_address_for_app_packet_after_netstack_callbacks(
            was_ack, dest_address);

    LOG_DBG("Flow destination ");
    LOG_DBG_LLADDR(dest_address);
    LOG_DBG_("\n");

    // If this was from an ACK, we are the transmitter and are thus interested
    // if the flow has TX cells
    uint8_t options = LINK_OPTION_RX;
    if(was_ack) {
      options = LINK_OPTION_TX;
    }

    if(!flow_has_link(source_address, dest_address, from, options)) {
      return true;
    }
    else {
      reset_link_timeout_by_properties(
          source_address, dest_address, from, options);
//      LOG_DBG("Flow already has link\n");
    }
  }
  else {
//    LOG_DBG("Not app packet\n");
  }
  return false;
}

/*---------------------------------------------------------------------------*/
static void
layered_packet_received(void)
{
  LOG_DBG("Packet received seqno %u\n",
          packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));

  linkaddr_t source_address = {0};
  linkaddr_t dest_address = {0};
  if(is_app_packet_without_dedicated_link(&source_address,
                                          &dest_address,
                                          packetbuf_addr(PACKETBUF_ADDR_SENDER),
                                          false)) {
    LOG_DBG("Received app-packet originated from ");
    LOG_DBG_LLADDR(&source_address);
    LOG_DBG_(" without dedicated link\n");
    if(!is_root() && linkaddr_cmp(&parent_linkaddr, &linkaddr_null)) {
      LOG_WARN("Not adding cells since direction is unknown without parent\n");
      return;
    }

    add_flow_rx_cells(&source_address, &dest_address,
                      packetbuf_addr(PACKETBUF_ADDR_SENDER),
                      packetbuf_direction_is_upwards(false),
                      get_current_depth());
  }
}

/*---------------------------------------------------------------------------*/
static void
layered_packet_sent(int mac_status)
{
  if(mac_status != MAC_TX_OK) {
    return;
  }
  LOG_DBG("ACK received seqno %u\n", packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));

  linkaddr_t source_address = {0};
  linkaddr_t dest_address = {0};
  if(is_app_packet_without_dedicated_link(&source_address,
                                          &dest_address,
                                          packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
                                          true)) {
    LOG_DBG("Received ACK for app-packet originated from ");
    LOG_DBG_LLADDR(&source_address);
    LOG_DBG_(" without dedicated link\n");
    if(!is_root() && linkaddr_cmp(&parent_linkaddr, &linkaddr_null)) {
      LOG_WARN("Not adding cells since direction is unknown without parent\n");
      return;
    }
#if !TEST_SKIP_QUARANTINE_AFTER_ROUTE_CHANGE
    if(!timer_expired(&route_change_timer)) {
      LOG_WARN("Not adding TX cells since parent recently changed\n");
      return;
    }
#endif
    add_flow_tx_cells(&source_address, &dest_address,
                      packetbuf_addr(PACKETBUF_ADDR_RECEIVER),
                      packetbuf_direction_is_upwards(true));
  }
}

/*---------------------------------------------------------------------------*/

static void
schedule_common_cells(void) {
  bool first = true;
  // Add common cells used for RPL, TSCH, and app. without flow cells
  for(uint16_t i = FIRST_COMMON_SLOT;
      i < LAYERED_SF_LEN;
      i += COMMON_SLOT_SPACING) {

    uint16_t timeslot = i;
    uint16_t channel = COMMON_CELL_CHANNEL;
    uint8_t options = COMMON_SLOT_OPTIONS;

    LOG_INFO("Adding common cell %u/%u\n", timeslot, channel);

    add_link(timeslot, channel, options,
             LINK_TYPE_ADVERTISING, &tsch_broadcast_address, &linkaddr_null,
             false, false, &linkaddr_null);
  }
}

static void
remove_all_flow_links(void) {
  LOG_WARN("Removing all flow-links\n");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void remove_all_flow_tx_links(bool direction_upward) {
  LOG_WARN("Removing all %s TX flow-links\n",
           direction_upward ? "upwards" : "downwards");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        layered_links[i].direction_upwards == direction_upward &&
        (layered_links[i].options & LINK_OPTION_TX) &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void
remove_all_upwards_flow_tx_links(void) {
  remove_all_flow_tx_links(true);
}

static void
remove_all_downwards_flow_tx_links(void) {
  remove_all_flow_tx_links(false);
}

static void
remove_downward_flow_tx_link(const linkaddr_t* address) {
  layered_link_t* link =
      get_enabled_link_by_address_options(address, LINK_OPTION_TX);
  if(link != NULL) {
    if(link->is_flow && !link->direction_upwards) {
      LOG_WARN("Removing downward TX flow-link\n");
      remove_link_by_ptr(link);
    }
    sync_links_with_schedule();
  }
}

static void
remove_all_flow_links_learned_via(const linkaddr_t* learned_via) {
  LOG_WARN("Removing all flow-links learned via ");
  LOG_WARN_LLADDR(learned_via);
  LOG_WARN_("\n");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        linkaddr_cmp(&(layered_links[i].learned_via), learned_via) &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void
remove_all_rx_flow_links_learned_via(const linkaddr_t* learned_via) {
  LOG_WARN("Removing all RX flow-links learned via ");
  LOG_WARN_LLADDR(learned_via);
  LOG_WARN_("\n");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        linkaddr_cmp(&(layered_links[i].learned_via), learned_via) &&
        layered_links[i].options == LINK_OPTION_RX &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void
remove_all_flow_tx_links_with_destination(const linkaddr_t* destination) {
  LOG_WARN("Removing all TX flow-links with destination ");
  LOG_WARN_LLADDR(destination);
  LOG_WARN_("\n");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        layered_links[i].options == LINK_OPTION_TX &&
        linkaddr_cmp(&(layered_links[i].dest_address), destination) &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void
remove_all_flow_tx_links_with_destination_and_not_learned_via(
    const linkaddr_t* destination, const linkaddr_t* learned_via) {
  LOG_WARN("Removing all TX flow-links with dest. ");
  LOG_WARN_LLADDR(destination);
  LOG_WARN_(" and not learned via ");
  LOG_WARN_LLADDR(learned_via);
  LOG_WARN_("\n");
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied &&
        layered_links[i].is_flow &&
        layered_links[i].options == LINK_OPTION_TX &&
        linkaddr_cmp(&(layered_links[i].dest_address), destination) &&
        !linkaddr_cmp(&(layered_links[i].learned_via), learned_via) &&
        link_is_enabled(&layered_links[i])) {
      remove_link_by_ptr(&layered_links[i]);
    }
  }
  sync_links_with_schedule();
}

static void
route_callback(int event,
               const uip_ipaddr_t *route,
               const uip_ipaddr_t *next_hop,
               int num_routes,
               bool route_update) {

  rpl_dag_t* rpl_dag = rpl_get_any_dag();
  if(rpl_dag == NULL) {
    LOG_WARN("No dag!\n");
    remove_all_flow_links();
    last_depth = 0xffff;
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);
    return;
  }

  uint16_t depth = get_current_depth();
  if(depth == 0xffff) {
    LOG_WARN("Invalid depth!\n");
    // Remove all TX links
    remove_all_upwards_flow_tx_links();
    remove_all_downwards_flow_tx_links();
    last_depth = depth;
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);
    return;
  }

  if(last_depth != 0xffff &&
      depth != last_depth) {
    LOG_WARN("Changed depth! %u to %u\n", last_depth, depth);

    remove_all_upwards_flow_tx_links();
    remove_all_downwards_flow_tx_links();
    last_depth = depth;
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);
    return;
  }

  last_depth = depth;

  // Fetch the route link-layer address by dissecting the IP
  linkaddr_t route_lladdr = {{0}};
  uip_ds6_set_lladdr_from_iid((uip_lladdr_t*)&route_lladdr, route);

  if(event == UIP_DS6_NOTIFICATION_DEFRT_RM) {
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);
    LOG_INFO("Removed default route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_("\n");
    remove_all_upwards_flow_tx_links();
    return;
  }

  else if(event == UIP_DS6_NOTIFICATION_ROUTE_ADD) {
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);

    // Fetch the next-hop link-layer address by dissecting the IP
    linkaddr_t next_hop_lladdr = {{0}};
    uip_ds6_set_lladdr_from_iid((uip_lladdr_t*)&next_hop_lladdr, next_hop);

    LOG_INFO("Added route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_LLADDR(&next_hop_lladdr);
    LOG_INFO_("\n");

    // If we have TX-link towards this destination/route,
    // and it was learned by someone else than the next-hop of this
    // new route, we should remove them since the routing layer will
    // send towards this new next-hop but using the existing links -
    // which the new next-hop does not have RX cells for.
    remove_all_flow_tx_links_with_destination_and_not_learned_via(
        &route_lladdr, &next_hop_lladdr);
  }

  else if(event == UIP_DS6_NOTIFICATION_ROUTE_RM) {
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    timer_set(&parent_change_timer, PARENT_CHANGE_WAIT_TIMER);

    // Fetch the next-hop link-layer address by dissecting the IP
    linkaddr_t next_hop_lladdr = {{0}};
    uip_ds6_set_lladdr_from_iid((uip_lladdr_t*)&next_hop_lladdr, next_hop);

    LOG_INFO("Removed route ");
    LOG_INFO_6ADDR(route);
    LOG_INFO_(" / ");
    LOG_INFO_LLADDR(&route_lladdr);
    LOG_INFO_(" via ");
    LOG_INFO_LLADDR(&next_hop_lladdr);
    LOG_INFO_("\n");

//    // Alternative to the more optimized behavior below
//    // Just simply remove all downwards
//    remove_all_downwards_flow_tx_links();
//
//    // Remove all flows with this as destination
//    remove_all_flow_tx_links_with_destination(&route_lladdr);
//
//    return;

    // Remove all flows with this as destination
    remove_all_flow_tx_links_with_destination(&route_lladdr);

    // If this route is also the next-hop, it means we have lost the route
    // to a neighbor. The routing layer will now use the parent as next-hop for
    // any other routes through this neighbor, which will cause issues
    // since the parent does not have the flow-cells scheduled.
    // Therefore remove all link which we learned via this neighbor.
    // Potentially we could use a neigbhor rm callback instead of route
    // callback, but it was not clear if a route to a next-hop neighbor can
    // be removed, but it still remain in neighbor table.
    if(linkaddr_cmp(&route_lladdr, &next_hop_lladdr)) {
      LOG_DBG("Lost neighbor\n");
      remove_all_flow_links_learned_via(&route_lladdr);
    }
    else {
      // It was a route farther away, remove our TX flow-link from it
      // (always downward)
      remove_downward_flow_tx_link(&route_lladdr);
    }

    return;
  }
}

/*---------------------------------------------------------------------------*/

static void
new_time_source(const struct tsch_neighbor *old,
                const struct tsch_neighbor *new) {
  // We need to known the parent linkaddr to judge sent packets direction
  if(new != old) {
    const linkaddr_t *new_addr = tsch_queue_get_nbr_address(new);
    timer_set(&route_change_timer, ROUTE_CHANGE_WAIT_TIMER);
    if(new_addr != NULL) {
      linkaddr_copy(&parent_linkaddr, new_addr);
    } else {
      linkaddr_copy(&parent_linkaddr, &linkaddr_null);
    }
  }
}

/*---------------------------------------------------------------------------*/
static void
periodic_check() {
  check_link_timeouts();

  if(!schedule_in_sync()) {
    LOG_DBG("Schedule not in sync\n");
    sync_links_with_schedule();
  }

  ctimer_set(&ct_periodic, SCHEDULE_PERIODIC_CHECK_INTERVAL,
             periodic_check, NULL);
}

/*---------------------------------------------------------------------------*/

void
layered_last_packet_was_forwarding_error(const linkaddr_t* transmitter) {
#if TEST_SKIP_FWD_ERR
  return;
#endif

  if(!last_rx_link_overwritten.occupied) {
    LOG_WARN("No RX link to restore\n");
    return;
  }

  // The last packet was a forwarding error. Thus we might have made erroneous
  // changes to the schedule. Our worry is that we added a wrong RX cell in the
  // same timeslot as a correct one - thus deleting a correct RX cell.
  // Fix this by re-instating the last RX cell we deleted - if it was learned
  // by the transmitter of the forwarding-error packet.
  if(linkaddr_cmp(&last_rx_link_overwritten_trigger, transmitter)) {
    LOG_WARN("Restoring RX link\n");
    add_link_by_ptr(&last_rx_link_overwritten);
    last_rx_link_overwritten.occupied = false;
  }
  else {
    LOG_DBG("Last overwritten RX link was not from forwarding-error\n");
  }
}


void
layered_check_for_link_inconsistency(const rpl_parent_t* transmitter,
                                     const linkaddr_t* transmitter_addr,
                                     bool rpl_direction_upwards) {

#if TEST_SKIP_INCONSISTENCY
  return;
#endif

  if(!timer_expired(&parent_change_timer)) {
    LOG_INFO("Skipping incon check due route change\n");
    return;
  }
  if(!timer_expired(&new_neighbor_rx_timer)) {
    LOG_INFO("Skipping incon check due to new neighbor RX\n");
    return;
  }

  if(packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE) != PACKET_TYPE_APP) {
    return;
  }

  if(transmitter == NULL) {
    return;
  }

  uint16_t our_depth = get_current_depth();
  uint16_t transmitter_depth = transmitter->mc.obj.hop_count;
  if(our_depth == 0xffff || transmitter_depth == 0xffff) {
    return;
  }

  uint16_t our_expected_depth = 0;
  if(rpl_direction_upwards) {
    our_expected_depth = transmitter_depth - 1;
  }
  else {
    our_expected_depth = transmitter_depth + 1;
  }

  if(our_depth != our_expected_depth) {
    // This packet came from a TXer with unexpected depth
    // Remove all RX cells from him
    LOG_WARN("TXer depth %u, our expected depth %u, our depth %u\n",
             transmitter_depth, our_expected_depth, our_depth);
    // Tested and found without advantage
//    remove_all_flow_links_learned_via(transmitter_addr);
    remove_all_rx_flow_links_learned_via(transmitter_addr);
    return;
  }

  if(index_for_last_rx_link_added == -1) {
    return;
  }

  layered_link_t last_rx_link_added =
      layered_links[index_for_last_rx_link_added];


  // Reset the index so that we don't re-check
  index_for_last_rx_link_added = -1;

  if(!linkaddr_cmp(&(last_rx_link_added.learned_via), transmitter_addr)) {
//    LOG_DBG("Last added RX-link was not learned from the TXer\n");
    return;
  }

  if(last_rx_link_added.direction_upwards != rpl_direction_upwards) {

    LOG_WARN("Direction inconsistency for RX link, should be %s:\n",
             rpl_direction_upwards ? "upwards" : "downwards");
    link_print(&last_rx_link_added);

    // Remove all RX links to this neighbor to poison his ETX
    remove_all_rx_flow_links_learned_via(transmitter_addr);
    return;
  }

  return;
}

/*---------------------------------------------------------------------------*/
static void
init(uint16_t sf_handle)
{
  // Run time check of channels as preprocessor does not support sizeof
  if(NUM_CHANNELS % 2 != 0) {
    LOG_ERR("PANIC: Num. channels must be an even number, not %d\n", NUM_CHANNELS);
    return;
  }

  // Register for route changes
  static struct uip_ds6_notification n;
  uip_ds6_notification_add(&n, route_callback);
  LOG_INFO("Registered for route changes\n");
  LOG_INFO("Parent switch wait timer: %d s\n",
           ROUTE_CHANGE_WAIT_TIMER / CLOCK_SECOND);
  LOG_INFO("Link timeout: %d s\n", LAYERED_LINK_TIMEOUT_SEC);

  slotframe_handle = sf_handle;

  /* Slotframe for unicast transmissions */
  sf_layered = tsch_schedule_add_slotframe(
      slotframe_handle, LAYERED_SF_LEN);

#if RUN_TESTS
  LOG_WARN("Running tests\n");
  if(!tests()) {
    LOG_ERR("PANIC: Tests failed\n");
  }
  else {
    LOG_WARN("Tests OK\n");
  }
#endif

  netstack_sniffer_add(&layered_sniffer);

  schedule_common_cells();

  tsch_schedule_print();

  ctimer_set(&ct_periodic, SCHEDULE_PERIODIC_CHECK_INTERVAL,
             periodic_check, NULL);
}

/*---------------------------------------------------------------------------*/
struct layered_rule layered_divergecast = {
  init,
  new_time_source,
  NULL,
  NULL,
  NULL,
  "layered divergecast",
};

/*---------------------------------------------------------------------------*/

#if RUN_TESTS
static bool test_channel_calc(
    int depth, bool upwards_direction, int expected) {
  int result = calculate_channel(depth, upwards_direction);
  if(result != expected) {
    LOG_ERR("Channel was %d for depth %d, dir %d, expected %d\n",
            result, depth, upwards_direction, expected);
    return false;
  }
  return true;
}

static int test_channels_calc(void) {
  int success = 1;
  success *= test_channel_calc(0, true, 1);
  success *= test_channel_calc(1, true, 1);
  success *= test_channel_calc(2, true, 2);
  success *= test_channel_calc(3, true, 2);
  success *= test_channel_calc(4, true, 1);
  success *= test_channel_calc(5, true, 1);

  success *= test_channel_calc(0, false, 3);
  success *= test_channel_calc(1, false, 3);
  success *= test_channel_calc(2, false, 4);
  success *= test_channel_calc(3, false, 4);
  success *= test_channel_calc(4, false, 3);
  success *= test_channel_calc(5, false, 3);

  return success;
}

static bool test_timeslot_calc(
    const linkaddr_t *linkaddr, uint16_t layer, int expected) {
  int result = calculate_timeslot(linkaddr, layer);
  if(result != expected) {
    LOG_ERR("Timeslot was %d for addr %u, layer %d, expected %d\n",
            result, linkaddr->u8[7], layer, expected);
    return false;
  }
  return true;
}

static int test_timeslots_calc(void) {
  int success = 1;
  linkaddr_t linkaddr = {0};
  // assuming grenoble setup (17 nodes, 9 CS spacing) and no deployment hash
  linkaddr.u8[7] = 1;
  success *= test_timeslot_calc(&linkaddr, 1, 0);
  success *= test_timeslot_calc(&linkaddr, 2, 19);
  linkaddr.u8[7] = 2;
  success *= test_timeslot_calc(&linkaddr, 1, 1);
  success *= test_timeslot_calc(&linkaddr, 2, 20);
  linkaddr.u8[7] = 3;
  success *= test_timeslot_calc(&linkaddr, 1, 2);
  success *= test_timeslot_calc(&linkaddr, 2, 21);
  linkaddr.u8[7] = 4;
  success *= test_timeslot_calc(&linkaddr, 1, 3);
  success *= test_timeslot_calc(&linkaddr, 2, 22);
  linkaddr.u8[7] = 5;
  success *= test_timeslot_calc(&linkaddr, 1, 4);
  success *= test_timeslot_calc(&linkaddr, 2, 23);
  linkaddr.u8[7] = 6;
  success *= test_timeslot_calc(&linkaddr, 1, 5);
  success *= test_timeslot_calc(&linkaddr, 2, 24);
  linkaddr.u8[7] = 7;
  success *= test_timeslot_calc(&linkaddr, 1, 6);
  success *= test_timeslot_calc(&linkaddr, 2, 25);
  linkaddr.u8[7] = 8;
  success *= test_timeslot_calc(&linkaddr, 1, 7);
  success *= test_timeslot_calc(&linkaddr, 2, 27);
  linkaddr.u8[7] = 9;
  success *= test_timeslot_calc(&linkaddr, 1, 9);
  success *= test_timeslot_calc(&linkaddr, 2, 28);
  linkaddr.u8[7] = 10;
  success *= test_timeslot_calc(&linkaddr, 1, 10);
  success *= test_timeslot_calc(&linkaddr, 2, 29);
  linkaddr.u8[7] = 11;
  success *= test_timeslot_calc(&linkaddr, 1, 11);
  success *= test_timeslot_calc(&linkaddr, 2, 30);
  linkaddr.u8[7] = 12;
  success *= test_timeslot_calc(&linkaddr, 1, 12);
  success *= test_timeslot_calc(&linkaddr, 2, 31);
  linkaddr.u8[7] = 13;
  success *= test_timeslot_calc(&linkaddr, 1, 13);
  success *= test_timeslot_calc(&linkaddr, 2, 32);
  linkaddr.u8[7] = 14;
  success *= test_timeslot_calc(&linkaddr, 1, 14);
  success *= test_timeslot_calc(&linkaddr, 2, 33);
  linkaddr.u8[7] = 15;
  success *= test_timeslot_calc(&linkaddr, 1, 15);
  success *= test_timeslot_calc(&linkaddr, 2, 34);
  linkaddr.u8[7] = 16;
  success *= test_timeslot_calc(&linkaddr, 1, 16);
  success *= test_timeslot_calc(&linkaddr, 2, 36);
  linkaddr.u8[7] = 17;
  success *= test_timeslot_calc(&linkaddr, 1, 18);
  success *= test_timeslot_calc(&linkaddr, 2, 37);

  return success;
}

static int test_calculate_layer(uint16_t depth, int expected) {
  int result = calculate_layer(depth);
  if(result != expected) {
    LOG_ERR("Layer was %d for depth %u, expected %d\n",
            result, depth, expected);
    return false;
  }
  return true;
}

static int test_calculate_layers(void) {
  int success = 1;
  success *= test_calculate_layer(0, 2);
  success *= test_calculate_layer(1, 1);
  success *= test_calculate_layer(2, 2);
  success *= test_calculate_layer(3, 1);

  return success;
}

static int test_links_list_helper_enabled_count(int expected) {
  int count = 0;
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(link_is_enabled(&(layered_links[i]))) {
      count++;
    }
  }
  if(count != expected) {
    LOG_ERR("Enabled count was %d, expected %d\n", count, expected);
    return false;
  }
  return true;
}

static int test_links_list_helper_occupied_count(int expected) {
  int count = 0;
  for(int i = 0; i < MAX_NUM_LINKS; i++) {
    if(layered_links[i].occupied) {
      count++;
    }
  }
  if(count != expected) {
    LOG_ERR("Occupied count was %d, expected %d\n", count, expected);
    return false;
  }
  return true;
}

static void test_links_list_print(layered_link_t* link) {
  link_print(link);
}

static int test_links_list_helper_compare(
    layered_link_t* link1, layered_link_t* link2) {
  if(link1 == NULL || link2 == NULL) {
    LOG_ERR("Link NULL when comparing\n");
    return false;
  }

  if(link1->timeslot != link2->timeslot ||
      link1->channel != link2->channel ||
      link1->options != link2->options ||
      link1->link_type != link2->link_type ||
      link1->direction_upwards != link2->direction_upwards ||
      link1->is_flow != link2->is_flow ||
      linkaddr_cmp(&(link1->address), &(link2->address)) == 0) {
    LOG_ERR("Link1 not identical to link2\n");
    test_links_list_print(link1);
    test_links_list_print(link2);
    return false;
  }
  return true;
}

static void test_links_list_helper_add(layered_link_t* link) {
  add_link(link->timeslot, link->channel,
           link->options, link->link_type,
           &(link->address), link->direction_upwards, link->is_flow);
}

static void test_links_list_helper_remove(layered_link_t* link) {
  remove_link(link->timeslot, link->channel);
}

static layered_link_t* test_links_list_get_identical_link(
    layered_link_t* link) {
  return get_identical_link(
      link->timeslot, link->channel,
      link->options, link->link_type,
      &(link->address),
      link->direction_upwards, link->is_flow);
}

static int test_links_list_manipulations(void) {
  int success = 1;
  layered_link_t* link = {0};

  layered_link_t test_link1 = {
      .timeslot = 0,
      .channel = 1,
      .options = LINK_OPTION_RX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
      .direction_upwards = true,
      .is_flow = false
  };

  layered_link_t test_link2 = {
      .timeslot = 1,
      .channel = 2,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = false,
      .is_flow = false
  };


  // Test add
  test_links_list_helper_add(&test_link1);
  test_links_list_helper_add(&test_link2);

  success *= test_links_list_helper_occupied_count(2);
  success *= test_links_list_helper_enabled_count(2);
  if(!success) {
    LOG_INFO("Test add failed\n");
  }


  // Test remove
  test_links_list_helper_remove(&test_link1);
  success *= test_links_list_helper_occupied_count(2);
  success *= test_links_list_helper_enabled_count(1);

  test_links_list_helper_remove(&test_link2);
  success *= test_links_list_helper_occupied_count(2);
  success *= test_links_list_helper_enabled_count(0);
  if(!success) {
    LOG_INFO("Test remove failed\n");
  }


  // Test re-add
  test_links_list_helper_add(&test_link1);
  test_links_list_helper_add(&test_link2);
  success *= test_links_list_helper_occupied_count(2);
  success *= test_links_list_helper_enabled_count(2);
  if(!success) {
    LOG_INFO("Test re-add same failed\n");
  }


  // Test gets
  link = get_link(0, 1);
  success *= test_links_list_helper_compare(link, &test_link1);
  link = get_link(1, 2);
  success *= test_links_list_helper_compare(link, &test_link2);
  if(!success) {
    LOG_INFO("Test get failed\n");
  }


  // Test enabled
  link = get_link(0, 1);
  if(!link_is_enabled(link)) {
    success = 0;
  }
  link = get_link(1, 2);
  if(!link_is_enabled(link)) {
    success = 0;
  }
  if(!success) {
    LOG_INFO("Test link enabled failed\n");
  }


  // Test identical get
  link = test_links_list_get_identical_link(&test_link1);
  success *= test_links_list_helper_compare(link, &test_link1);
  link = test_links_list_get_identical_link(&test_link2);
  success *= test_links_list_helper_compare(link, &test_link2);
  if(!success) {
    LOG_INFO("Test get identical failed\n");
  }


  // Test timeslot get
  link = get_enabled_link_in_timeslot(0);
  success *= test_links_list_helper_compare(link, &test_link1);
  link = get_enabled_link_in_timeslot(1);
  success *= test_links_list_helper_compare(link, &test_link2);
  if(!success) {
    LOG_INFO("Test get timeslot failed\n");
  }


  // Test index
  if(get_available_index() != 2) {
    success = 0;
  }
  if(!success) {
    LOG_INFO("Test index failed\n");
  }


  // Test adding cell in same TS but different channel
  layered_link_t test_link3 = {
      .timeslot = 2,
      .channel = 2,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = false,
      .is_flow = false
  };
  layered_link_t test_link4 = {
      .timeslot = 2,
      .channel = 3,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = false,
      .is_flow = false
  };

  test_links_list_helper_add(&test_link3);
  test_links_list_helper_add(&test_link4);

  link = get_link(2, 3);
  success *= test_links_list_helper_compare(link, &test_link4);

  success *= test_links_list_helper_occupied_count(4);
  success *= test_links_list_helper_enabled_count(3);
  if(!success) {
    LOG_INFO("Test add same TS different CH failed\n");
  }


  // Test adding cell in same TS and channel
  layered_link_t test_link5 = {
      .timeslot = 3,
      .channel = 3,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = false,
      .is_flow = false
  };

  layered_link_t test_link6 = {
      .timeslot = 3,
      .channel = 3,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = false,
      .is_flow = false
  };

  // Same but different direction
  layered_link_t test_link7 = {
      .timeslot = 3,
      .channel = 3,
      .options = LINK_OPTION_TX,
      .link_type = LINK_TYPE_NORMAL,
      .address = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
      .direction_upwards = true,
      .is_flow = false
  };

  test_links_list_helper_add(&test_link5);
  test_links_list_helper_add(&test_link6);

  link = get_link(3, 3);
  success *= test_links_list_helper_compare(link, &test_link6);
  success *= test_links_list_helper_occupied_count(5);
  success *= test_links_list_helper_enabled_count(4);

  test_links_list_helper_add(&test_link7);

  success *= test_links_list_helper_occupied_count(5);
  success *= test_links_list_helper_enabled_count(4);
  link = get_link(3, 3);
  success *= test_links_list_helper_compare(link, &test_link7);
  if(!success) {
    LOG_INFO("Test add same TS same CH failed\n");
  }


  // Test scheduling syncing
  if(schedule_in_sync()){
    success = 0;
  }
  sync_links_with_schedule();
  if(!schedule_in_sync()){
    success = 0;
  }
  if(!success) {
    LOG_INFO("Test sync failed\n");
  }


  // Cleanup
  test_links_list_helper_remove(&test_link1);
  test_links_list_helper_remove(&test_link2);
  test_links_list_helper_remove(&test_link3);
  test_links_list_helper_remove(&test_link4);
  test_links_list_helper_remove(&test_link5);
  test_links_list_helper_remove(&test_link6);
  test_links_list_helper_remove(&test_link7);
  success *= test_links_list_helper_enabled_count(0);
  if(!schedule_in_sync()){
    success = 0;
  }
  if(!success) {
    LOG_INFO("Test cleanup failed\n");
  }

  return success;
}

static int test_packet_direction(bool was_tx, const linkaddr_t* sender,
                                 const linkaddr_t* receiver,
                                 const linkaddr_t* parent, bool expected) {
  bool result = packet_direction_is_upwards(was_tx, sender, receiver, parent);
  if(result != expected) {
    LOG_ERR("Direction was %d, expected %d\n", result, expected);
    LOG_ERR("was_tx %d, sender ", was_tx);
    LOG_ERR_LLADDR(sender);
    LOG_ERR_(", receiver ");
    LOG_ERR_LLADDR(receiver);
    LOG_ERR_(", parent ");
    LOG_ERR_LLADDR(parent);
    LOG_ERR_("\n");
    return false;
  }
  return true;
}

static int test_packet_directions(void) {
  int success = 1;

  linkaddr_t sender1 = {0};
  sender1.u8[LINKADDR_SIZE - 1] = 1;
  linkaddr_t sender2 = {0};
  sender2.u8[LINKADDR_SIZE - 1] = 2;

  linkaddr_t receiver1 = {0};
  receiver1.u8[LINKADDR_SIZE - 1] = 1;
  linkaddr_t receiver2 = {0};
  receiver2.u8[LINKADDR_SIZE - 1] = 2;

  linkaddr_t parent1 = {0};
  parent1.u8[LINKADDR_SIZE - 1] = 1;
  linkaddr_t parent2 = {0};
  parent2.u8[LINKADDR_SIZE - 1] = 2;

  success *= test_packet_direction(true, &sender1, &receiver2, &parent1, false);
  success *= test_packet_direction(true, &sender1, &receiver2, &parent2, true);
  success *= test_packet_direction(true, &sender2, &receiver2, &parent1, false);
  success *= test_packet_direction(true, &sender2, &receiver2, &parent2, true);

  success *= test_packet_direction(false, &sender1, &receiver2, &parent1, false);
  success *= test_packet_direction(false, &sender2, &receiver2, &parent1, true);
  success *= test_packet_direction(false, &sender1, &receiver1, &parent1, false);
  success *= test_packet_direction(false, &sender2, &receiver1, &parent1, true);
  return success;
}

static int tests(void) {
  int success = 1;
  success *= test_channels_calc();
  // assuming grenoble setup (17 nodes, 9 CS spacing) and no deployment hash
  success *= test_timeslots_calc();
  success *= test_calculate_layers();
  success *= test_links_list_manipulations();
  success *= test_packet_directions();
  return success;
}
#endif

/*---------------------------------------------------------------------------*/
