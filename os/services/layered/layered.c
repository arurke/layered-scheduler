#include "layered.h"
#include "contiki.h"
#include "net/packetbuf.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/routing/routing.h"
#if ROUTING_CONF_RPL_CLASSIC
#include "net/routing/rpl-classic/rpl.h"
#include "net/routing/rpl-classic/rpl-private.h"
#endif

/*---------------------------------------------------------------------------*/

#include "sys/log.h"
#define LOG_MODULE "Layered"
#define LOG_LEVEL   LOG_LEVEL_LAYERED

/*---------------------------------------------------------------------------*/

#ifndef BUILD_WITH_PACKET_TYPE
#error Layered requires BUILD_WITH_PACKET_TYPE
#endif

#ifndef BUILD_WITH_LAYERED
#error Layered requires BUILD_WITH_LAYERED
#endif

#if ROUTING_CONF_RPL_LITE
#error Layered supports only RPL CLASSIC
#endif

/*---------------------------------------------------------------------------*/

const struct layered_rule *all_rules[] = LAYERED_RULES;
#define NUM_RULES (sizeof(all_rules) / sizeof(struct layered_rule *))

// For gruesome source addr heuristics
#define HOP_LIMIT_MASK            0x03
#define SIXLO_HEADER_PART2_OFFSET 1
#define SRC_ADDR_MODE_MASK        0x30
#define SRC_ADDR_OFFSET           3

/*---------------------------------------------------------------------------*/
// Does not work for all situations of RXed packets. Use uipbuf version for
// those
static bool
find_source_address(
    const uint8_t* data, uint16_t data_len,
    linkaddr_t* source_lladdr, bool after_ack) {
  // Hack to figure out the originating node address

  LOG_DBG("Fetching source address, data len %u\n", data_len);
//  LOG_DBG("Start data 0x%02x%02x\n", *data, *(data+1));
//
//  LOG_DBG("UIP_BUF SAYS: ");
//  LOG_DBG_("packet received from ");
//  LOG_DBG_6ADDR(&UIP_IP_BUF->srcipaddr);
//  LOG_DBG_("\n");

  if(data_len < 12) {
    LOG_ERR("PANIC: Too short for source address!\n");
    return false;
  }

//  LOG_DBG("Len: %u. 0x", data_len);
//  for(int i = 0; i < data_len; i++) {
//    LOG_DBG_("%02x", data[i]);
//  }
//  LOG_DBG_("\n");

  if(after_ack) {
    // If this is after we have TXed, the l2 header has been added
    // to the packetbuf data. We therefore must skip that first.
    // We hardcode 21 bytes. TODO This will not work with security++
    data += 21;
//    LOG_DBG("Skipping L2 header, now at 0x%02x%02x\n", *data, *(data+1));
  }

  // Is source address compressed? If yes, we are the source
  bool source_address_compressed = false;
  if(((*(data + SIXLO_HEADER_PART2_OFFSET)) & SRC_ADDR_MODE_MASK) == 0x30) {
    memcpy(source_lladdr, &linkaddr_node_addr, sizeof(linkaddr_t));
    LOG_DBG("We are the source because source address is compressed\n");
    source_address_compressed = true;
    return true;
  }

  uint8_t src_addr_offset = 0;
  if(!source_address_compressed) {
    src_addr_offset += SRC_ADDR_OFFSET;
  }

  // Has inline hop limit? This moves the source addr one byte
  if(((*data) & HOP_LIMIT_MASK) == 0) {
    src_addr_offset++;
//    LOG_DBG("Inline hoplimit\n");
  }

//  LOG_DBG("Fetching address at 0x%02x%02x\n",
//          *(data+src_addr_offset), *(data+src_addr_offset+1));

  linkaddr_t* fetched_source_address = (linkaddr_t*)(data + src_addr_offset);

  // Create an ipaddr and fill the interface id from the buf
  uip_ipaddr_t ipaddr = {0};
  memcpy(ipaddr.u8 + 8, fetched_source_address->u8, LINKADDR_SIZE);

  // Use ds6 to properly decode lladdr from IP.
  uip_ds6_set_lladdr_from_iid((uip_lladdr_t*) source_lladdr, &ipaddr);

  // This may be called by TSCH
  LOG_DBG("Found source address ");
  LOG_DBG_LLADDR(source_lladdr);
  LOG_DBG_("\n");
  return true;
}
/*---------------------------------------------------------------------------*/
// Does not work for all situations of RXed packets. Use uipbuf version for
// those
static bool
find_dest_address(
    const uint8_t* data, uint16_t data_len,
    linkaddr_t* dest_lladdr, bool after_ack) {
  // Hack to figure out the originating node address

  LOG_DBG("Fetching dest address, data len %u\n", data_len);
//  LOG_DBG("Start data 0x%02x%02x\n", *data, *(data+1));
//
//  LOG_DBG("UIP_BUF SAYS: ");
//  LOG_DBG_("packet received from ");
//  LOG_DBG_6ADDR(&UIP_IP_BUF->srcipaddr);
//  LOG_DBG_("\n");

  if(data_len < 12) {
    LOG_ERR("PANIC: Too short for dest address!\n");
    return false;
  }

//  LOG_DBG("Len: %u. 0x", data_len);
//  for(int i = 0; i < data_len; i++) {
//    LOG_DBG_("%02x", data[i]);
//  }
//  LOG_DBG_("\n");

  if(after_ack) {
    // If this is after we have TXed, the l2 header has been added
    // to the packetbuf data. We therefore must skip that first.
    // We hardcode 21 bytes. TODO This will not work with security++
    data += 21;
//    LOG_DBG("Skipping L2 header, now at 0x%02x%02x\n", *data, *(data+1));
  }

  // Has inline hop limit? This moves the source addr one byte
  uint8_t dest_addr_offset = 0;
  if(((*data) & HOP_LIMIT_MASK) == 0) {
    dest_addr_offset++;
//    LOG_DBG("Inline hoplimit\n");
  }

//  LOG_DBG("header part 1 and part 2 and part 3 0x%02x%02x%02x\n", *data, *(data+1), *(data+2));

  if(((*(data + SIXLO_HEADER_PART2_OFFSET)) & 0x03) == 0x03) {
    LOG_DBG("Destination compressed, thus L2 destination is IP destination\n");
    linkaddr_copy(dest_lladdr, &linkaddr_null);
    return true;
  }


  // Is source address compressed?
  bool source_address_compressed = false;
  if(((*(data + SIXLO_HEADER_PART2_OFFSET)) & SRC_ADDR_MODE_MASK) == 0x30) {
    LOG_DBG("We are the source because source address is compressed\n");
    source_address_compressed = true;
  }

  // Skip the header regardless
  dest_addr_offset += SRC_ADDR_OFFSET;

  if(!source_address_compressed) {
    dest_addr_offset += LINKADDR_SIZE;
  }

//  LOG_DBG("Fetching address at ");
//  for(int i = 0; i<10; i++) {
//    LOG_DBG_("%02x", *(data+dest_addr_offset-2+i));
//  }
//  LOG_DBG_("\n");
//  dest_addr_offset-5;
//

  linkaddr_t* fetched_dest_address = (linkaddr_t*)(data + dest_addr_offset);

  // Create an ipaddr and fill the interface id from the buf
  uip_ipaddr_t ipaddr = {0};
  memcpy(ipaddr.u8 + 8, fetched_dest_address->u8, LINKADDR_SIZE);

  // Use ds6 to properly decode lladdr from IP.
  uip_ds6_set_lladdr_from_iid((uip_lladdr_t*) dest_lladdr, &ipaddr);

  // This may be called by TSCH
  LOG_DBG("Found dest address ");
  LOG_DBG_LLADDR(dest_lladdr);
  LOG_DBG_("\n");
  return true;
}

/*---------------------------------------------------------------------------*/
// Assumes uipbuf is set correctly, typically used in netstack RX callbacks
void
layered_get_source_address_uipbuf(linkaddr_t* source_lladdr) {
  if(uip_len == 0) {
    LOG_ERR("PANIC: uip_len is zero when searching for source address\n");
  }

  uip_ds6_set_lladdr_from_iid(
      (uip_lladdr_t*) source_lladdr, &UIP_IP_BUF->srcipaddr);

  LOG_DBG("Found source address via uipbuf: ");
  LOG_DBG_LLADDR(source_lladdr);
  LOG_DBG_("\n");
}
/*---------------------------------------------------------------------------*/
// Assumes uipbuf is set correctly, typically used in netstack RX callbacks
void
layered_get_dest_address_uipbuf(linkaddr_t* dest_lladdr) {
  if(uip_len == 0) {
    LOG_ERR("PANIC: uip_len is zero when searching for dest address\n");
  }

  uip_ds6_set_lladdr_from_iid(
      (uip_lladdr_t*) dest_lladdr, &UIP_IP_BUF->destipaddr);

  LOG_DBG("Found dest address via uipbuf: ");
  LOG_DBG_LLADDR(dest_lladdr);
  LOG_DBG_("\n");
}
/*---------------------------------------------------------------------------*/
bool
layered_get_source_address_for_app_packet_after_netstack_callbacks(
    bool after_ack, linkaddr_t* source_address) {

  if(!after_ack) {
    LOG_DBG("Finding source address in a RXed packet, using uipbuf\n");
    layered_get_source_address_uipbuf(source_address);
    return true;
  }

  LOG_DBG("Finding source address after a TX, using heuristic\n");
  if(!find_source_address(
      packetbuf_dataptr(), packetbuf_datalen(), source_address, after_ack)) {
    // Unable to find the source address, this should not happen
    LOG_ERR("PANIC: Unable to find source address!\n");
    return false;
  }

  return true;
}
/*---------------------------------------------------------------------------*/
bool
layered_get_dest_address_for_app_packet_after_netstack_callbacks(
    bool after_ack, linkaddr_t* dest_address) {

  if(!after_ack) {
    LOG_DBG("Finding dest address in a RXed packet, using uipbuf\n");
    layered_get_dest_address_uipbuf(dest_address);
    return true;
  }

//  LOG_ERR("Finding dest address after a TX, not supported\n");
//  return false;
  if(!find_dest_address(
      packetbuf_dataptr(), packetbuf_datalen(), dest_address, after_ack)) {
    // Unable to find the dest address, this should not happen
    LOG_ERR("PANIC: Unable to find dest address!\n");
    return false;
  }

  if(linkaddr_cmp(dest_address, &linkaddr_null)) {
    // Destination address is L2 destination address
    linkaddr_copy(dest_address, packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  }

  return true;
}
/*---------------------------------------------------------------------------*/
bool
layered_get_source_address_for_app_packet(const uint8_t* data,
                                           uint16_t data_len,
                                           linkaddr_t* source_address) {
  if(!find_source_address(data, data_len, source_address, false)) {
    // Unable to find the source address, this should not happen
    LOG_ERR("PANIC: Unable to find source address!\n");
    return false;
  }
  return true;
}

/*---------------------------------------------------------------------------*/
bool
layered_get_flow_address_for_app_packet(const uint8_t* data, uint16_t data_len,
                                        linkaddr_t* flow_address) {
  if(!layered_get_source_address_for_app_packet(
      data, data_len, flow_address)) {
    return false;
  }

  // Convert the source address into its flow address
  tsch_schedule_convert_to_flow_address(flow_address);
//  LOG_DBG("Flow packet\n");
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
      return layered_get_flow_address_for_app_packet(
          data, data_len, flow_address);
    case PACKET_TYPE_BEACON:
    case PACKET_TYPE_RPL:
    case PACKET_TYPE_KEEPALIVE:
    default:
//      LOG_DBG("Not flow packet\n");
      return false;
  }
}

/*---------------------------------------------------------------------------*/
void
layered_callback_new_time_source(
    const struct tsch_neighbor *old, const struct tsch_neighbor *new)
{
  // As with orchestra: Assume that the time source is also the RPL parent.
  // This is the case if the following is set:
  // #define RPL_CALLBACK_PARENT_SWITCH tsch_rpl_callback_parent_switch
  for(int i = 0; i < NUM_RULES; i++) {
    if(all_rules[i]->new_time_source != NULL) {
      all_rules[i]->new_time_source(old, new);
    }
  }
}

/*---------------------------------------------------------------------------*/
void
layered_init(void)
{
  int i;
  for(i = 0; i < NUM_RULES; i++) {
    LOG_INFO("Initializing rule %s (%u)\n", all_rules[i]->name, i);
    if(all_rules[i]->init != NULL) {
      all_rules[i]->init(i);
    }
  }

  LOG_INFO("Max. nodes %u, lay. %u, #ch. %lu, CS int. %d, CS %d, "\
           "SF len %u, stateful %d\n",
           LAYERED_MAX_NUM_NODES, LAYERED_NUM_LAYERS,
           (unsigned long) LAYERED_NUM_CHANNELS, LAYERED_COMMON_SLOT_SPACING,
           NUM_COMMON_SLOTS, LAYERED_SF_LEN, LAYERED_STATEFUL);
}
/*---------------------------------------------------------------------------*/
