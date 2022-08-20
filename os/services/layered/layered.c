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

const struct layered_rule *all_rules[] = LAYERED_RULES;
#define NUM_RULES (sizeof(all_rules) / sizeof(struct layered_rule *))

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

  LOG_INFO("Max nodes %u, layers %u, channels %lu, common slots %d, SF len %u\n",
           LAYERED_MAX_NUM_NODES, LAYERED_NUM_LAYERS,
           (unsigned long) LAYERED_NUM_CHANNELS,
           NUM_COMMON_SLOTS, LAYERED_SF_LEN);
}
/*---------------------------------------------------------------------------*/
