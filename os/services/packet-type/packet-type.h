#ifndef PACKET_TYPE_H
#define PACKET_TYPE_H

#include <stdint.h>

/*---------------------------------------------------------------------------*/

typedef enum {
  PACKET_TYPE_APP = 1,
  PACKET_TYPE_BEACON = 2,
  PACKET_TYPE_RPL = 3,
  PACKET_TYPE_KEEPALIVE = 4
} packet_type_t;

/*---------------------------------------------------------------------------*/

/**
 * \brief Sets packet-type into packetbuf based on given data
 * \return The packet-type
 */
packet_type_t packet_type_set(
    uint16_t frame_type, const uint8_t* data, uint16_t data_len);

/**
 * \brief Sets packet-type into packetbuf based on packetbuf
 * \return The packet-type
 */
packet_type_t packet_type_set_from_packetbuf(void);

/**
 * \brief Gets packet-type based on given data
 * \return The packet-type
 */
packet_type_t packet_type_get(
    uint16_t frame_type, const uint8_t* data, uint16_t data_len);

/*---------------------------------------------------------------------------*/

#endif /* PACKET_TYPE_H */
