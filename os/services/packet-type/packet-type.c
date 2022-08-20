#include "packet-type.h"
#include "packetbuf.h"
#include "frame802154.h"

#if !BUILD_WITH_PACKET_TYPE
#error BUILD_WITH_PACKET_TYPE must be set
#endif

/*---------------------------------------------------------------------------*/

#include "sys/log.h"
#define LOG_MODULE "PacketType"
#define LOG_LEVEL  LOG_LEVEL_MAC

/*---------------------------------------------------------------------------*/

// For gruesome RPL heuristics
#define SIXLO_NEXT_HEADER_OFFSET  2
#define SIXLO_NEXT_HEADER_LEN     3
#define ICMP_TYPE_OFFSET          0
#define ICMP_CODE_OFFSET          1
#define RPL_INSTANCE_ID_OFFSET    4

// For gruesome source addr heuristics
#define HOP_LIMIT_MASK            0x03
#define SIXLO_HEADER_PART2_OFFSET 1
#define SRC_ADDR_MODE_MASK        0x30
#define SRC_ADDR_OFFSET           3

/*---------------------------------------------------------------------------*/
// Find if packet is RPL by analyzing packet
static bool is_rpl_packet_heuristic(const uint8_t* data, uint16_t data_len) {

  if(data_len < 7) {
//    LOG_DBG("Too short for RPL\n");
    return false;
  }

  uint8_t sixlo_nh_len = SIXLO_NEXT_HEADER_LEN;

  // 6LoWPAN IPHC next-header field is 0x3a for ICMPv6
  if(*(data + SIXLO_NEXT_HEADER_OFFSET) != 0x3a) {
    return false;
  }

  // ICMP type, 0x9b is RPL
  if(*(data + sixlo_nh_len + ICMP_TYPE_OFFSET) != 0x9b) {
    // If it was a DIO or DIS, there is one extra byte in the 6lowpan header
    // for IPv6 dest addr. So lets check that offset as well
    sixlo_nh_len++;
    if(*(data + sixlo_nh_len + ICMP_TYPE_OFFSET) != 0x9b) {
      // no luck
      return false;
    }
  }

  // ICMP code, all RPL is below 0x8b
  if(*(data + sixlo_nh_len + ICMP_CODE_OFFSET) >= 0x8a) {
//    LOG_DBG("Byte %u 0x%02x\n", ICMP_CODE_OFFSET, *(data + 4));
    return false;
  }

  // RPL instance ID 0x1e (30)
  // This is not present in DIS, so let's just skip it
//  if(*(data + sixlo_nh_len + RPL_INSTANCE_ID_OFFSET) != 0x1e) {
////    LOG_DBG("Byte %u 0x%02x\n", RPL_INSTANCE_ID_OFFSET, *(data + 7));
//    return false;
//  }

  return true;
}
/*---------------------------------------------------------------------------*/
// Find if packet is RPL by analyzing packetbuf
// TODO The attrs are not populated at the time we are called
//static bool is_rpl_packet_via_packetbuf(void) {
//  // For some reason, the OS stores protocol and type field in strange packetbuf-attrs
//  // Inspired by orchestra_packet_sent()
//  uint8_t protocol = packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID);
//  uint8_t icmp_type = (packetbuf_attr(PACKETBUF_ATTR_CHANNEL) >> 8) && 0x000000ff;
//
//  LOG_DBG("Packet protocol: %u, type: %u\n", protocol, icmp_type);
//
//  if(protocol == UIP_PROTO_ICMP6 && icmp_type == ICMP6_RPL) {
//    return true;
//  }
//  return false;
//}
/*---------------------------------------------------------------------------*/
static bool heuristic_is_keepalive(uint16_t data_len) {
  // Keep-alives are empty packets (only MAC headers)
  return data_len == 0;
}
/*---------------------------------------------------------------------------*/
static bool is_rpl_packet(const uint8_t* data, uint16_t data_len) {
//  return is_rpl_packet_via_packetbuf();
  return is_rpl_packet_heuristic(data, data_len);
}
/*---------------------------------------------------------------------------*/
static bool is_keepalive(uint16_t data_len) {
  return heuristic_is_keepalive(data_len);
}
/*---------------------------------------------------------------------------*/
static packet_type_t find_packet_type(
    uint16_t frame_type, const uint8_t* data, uint16_t data_len) {

  if(frame_type == FRAME802154_BEACONFRAME) {
    return PACKET_TYPE_BEACON;
  }

  if(is_rpl_packet(data, data_len)) {
    return PACKET_TYPE_RPL;
  }

  if(is_keepalive(data_len)) {
    return PACKET_TYPE_KEEPALIVE;
  }

  // Lastly assume it is application
  return PACKET_TYPE_APP;
}
/*---------------------------------------------------------------------------*/
packet_type_t packet_type_set(
    uint16_t frame_type, const uint8_t* data, uint16_t data_len) {
  packet_type_t packet_type = find_packet_type(frame_type, data, data_len);

  packetbuf_set_attr(PACKETBUF_ATTR_PACKET_TYPE, packet_type);
  return packet_type;
}
/*---------------------------------------------------------------------------*/
packet_type_t packet_type_set_from_packetbuf(void) {
  packet_type_t packet_type =
      find_packet_type(packetbuf_attr(PACKETBUF_ATTR_FRAME_TYPE),
                       packetbuf_dataptr(), packetbuf_datalen());

  packetbuf_set_attr(PACKETBUF_ATTR_PACKET_TYPE, packet_type);
  return packet_type;
}
/*---------------------------------------------------------------------------*/
packet_type_t packet_type_get(
    uint16_t frame_type, const uint8_t* data, uint16_t data_len) {
  return find_packet_type(frame_type, data, data_len);
}
/*---------------------------------------------------------------------------*/
