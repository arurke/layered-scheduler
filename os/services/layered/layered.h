/*
 * Copyright (c) 2022, Andreas Urke.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file Layered scheduler
 *
 * \author Andreas Urke <andrerur@stud.ntnu.no>
 */
#ifndef __LAYERED_H__
#define __LAYERED_H__

#include "layered-conf.h"
#include "net/mac/tsch/tsch.h"
#include "packet-type.h"
#if LAYERED_DIVERGECAST
#include "net/routing/rpl-classic/rpl.h"
#endif

/*---------------------------------------------------------------------------*/

// Layered rule, structure inherited from Orchestra. Most currently not in use.
struct layered_rule {
  void (* init)(uint16_t slotframe_handle);
  void (* new_time_source)(const struct tsch_neighbor *old, const struct tsch_neighbor *new);
  int  (* select_packet)(uint16_t *slotframe, uint16_t *timeslot, uint16_t *channel_offset);
  void (* child_added)(const linkaddr_t *addr);
  void (* child_removed)(const linkaddr_t *addr);
  const char *name;
};

struct layered_rule layered_multi_channel;
struct layered_rule layered_divergecast;

/*---------------------------------------------------------------------------*/

// Call from application to start Layered
void layered_init(void);

// Get source address for app. packet
bool layered_get_source_address_for_app_packet(const uint8_t* data,
                                               uint16_t data_len,
                                               linkaddr_t* flow_address);

// Get flow address for given packet
bool layered_get_flow_address_for_packet(uint16_t frame_type,
                                         const uint8_t* data,
                                         uint16_t data_len,
                                         linkaddr_t* flow_address);

// Get flow address for given app. packet
// Note! Does not work in netstack callbacks
bool layered_get_flow_address_for_app_packet(const uint8_t* data,
                                             uint16_t data_len,
                                             linkaddr_t* flow_address);

// Get flow address for given app. packet via uipbuf
// Assumes uipbuf is set correctly. Can by used in netstack callbacks.
void layered_get_source_address_uipbuf(linkaddr_t* source_lladdr);

bool
layered_get_source_address_for_app_packet_after_netstack_callbacks(
    bool after_ack, linkaddr_t* source_address);

bool
layered_get_dest_address_for_app_packet_after_netstack_callbacks(
    bool after_ack, linkaddr_t* dest_address);

// Set with
// #define TSCH_CALLBACK_NEW_TIME_SOURCE layered_callback_new_time_source
void layered_callback_new_time_source(
    const struct tsch_neighbor *old, const struct tsch_neighbor *new);

#if LAYERED_DIVERGECAST
void
layered_check_for_link_inconsistency(const rpl_parent_t* transmitter,
                                     const linkaddr_t* transmitter_addr,
                                     bool rpl_direction_upwards);

// Call if the last packet turned out to be a RPL forwarding error
void
layered_last_packet_was_forwarding_error(const linkaddr_t* transmitter);
#endif

#if LAYERED_STATS
void layered_stats_update(struct tsch_neighbor *n, struct tsch_packet *p,
                          struct tsch_link *link, uint8_t channel_offset,
                          uint8_t mac_tx_status);
void layered_print_stats();
#else
#define layered_stats_update(n, p, l, c, m)
#define layered_print_stats()
#endif

/*---------------------------------------------------------------------------*/
#endif /* __LAYERED_H__ */
