#ifndef __LAYERED_CONF_H__
#define __LAYERED_CONF_H__

#include "project-conf.h"
#include <stdint.h>

/*---------------------------------------------------------------------------*/

// Stateful implementation takes more RAM but catches e.g. failed allocations
#ifdef LAYERED_CONF_STATEFUL
#define LAYERED_STATEFUL              LAYERED_CONF_STATEFUL
#else
#define LAYERED_STATEFUL              0
#endif

#ifdef LOG_CONF_LEVEL_LAYERED
#define LOG_LEVEL_LAYERED             LOG_CONF_LEVEL_LAYERED
#else
#define LOG_LEVEL_LAYERED             LOG_LEVEL_INFO
#endif

#ifdef LAYERED_CONF_STATS
#define LAYERED_STATS                 LAYERED_CONF_STATS
#else
#define LAYERED_STATS                 0
#endif

// Including sink
#ifdef LAYERED_CONF_MAX_NUM_NODES
#define LAYERED_MAX_NUM_NODES         LAYERED_CONF_MAX_NUM_NODES
#else
#define LAYERED_MAX_NUM_NODES         50
#endif

#ifdef LAYERED_CONF_NUM_LAYERS
#define LAYERED_NUM_LAYERS            LAYERED_CONF_NUM_LAYERS
#else
#define LAYERED_NUM_LAYERS            2
#endif
#if LAYERED_NUM_LAYERS != 2
#error Only two layers are currently supported in Layered
#endif

#ifdef LAYERED_CONF_COMMON_SLOT_SPACING
#define LAYERED_COMMON_SLOT_SPACING   LAYERED_CONF_COMMON_SLOT_SPACING
#else
#define LAYERED_COMMON_SLOT_SPACING   37
#endif

#ifdef LAYERED_CONF_CHANNELS
#define LAYERED_CHANNELS              LAYERED_CONF_CHANNELS
#else
// Avoid channel offset 0 due to stats not supporting it.
#if LAYERED_DIVERGECAST
// Must be even number of channels at least 2
#define LAYERED_CHANNELS              (uint8_t[]){1,2,3,4}
#else
#define LAYERED_CHANNELS              (uint8_t[]){1,2}
#endif
#endif
#define LAYERED_NUM_CHANNELS          sizeof(LAYERED_CHANNELS)

// Time without traffic before de-scheduling a flow-link (divergecast only)
#ifndef LAYERED_CONF_LINK_TIMEOUT_SEC
#define LAYERED_LINK_TIMEOUT_SEC     7
#else
#define LAYERED_LINK_TIMEOUT_SEC     (LAYERED_CONF_LINK_TIMEOUT_SEC)
#endif

#ifndef LAYERED_CONF_ROUTE_CHANGE_WAIT_SEC
#define LAYERED_ROUTE_CHANGE_WAIT_SEC   2
#else
#define LAYERED_ROUTE_CHANGE_WAIT_SEC   (LAYERED_CONF_ROUTE_CHANGE_WAIT_SEC)
#endif

#ifndef LAYERED_CONF_PARENT_CHANGE_WAIT_SEC
#define LAYERED_PARENT_CHANGE_WAIT_SEC   10
#else
#define LAYERED_PARENT_CHANGE_WAIT_SEC   (LAYERED_CONF_PARENT_CHANGE_WAIT_SEC)
#endif

// Hash functions
#if BUILD_WITH_DEPLOYMENT
#include "services/deployment/deployment.h"
#define LAYERED_LINKADDR_HASH(addr)   deployment_id_from_lladdr(addr)
#else
#define LAYERED_LINKADDR_HASH(addr)   ((addr != NULL) ? (addr)->u8[LINKADDR_SIZE - 1] : -1)
#endif

// Num nodes * num layers + any common slots
#define COMMON_SLOT_SPACING           LAYERED_COMMON_SLOT_SPACING
#define LAYERED_RAW_SF_LEN            (LAYERED_MAX_NUM_NODES * LAYERED_NUM_LAYERS)
#define NUM_COMMON_SLOTS              (LAYERED_RAW_SF_LEN / (COMMON_SLOT_SPACING - 1))
#define LAYERED_SF_LEN                (LAYERED_RAW_SF_LEN + NUM_COMMON_SLOTS)

#ifdef LAYERED_CONF_RULES
#define LAYERED_RULES LAYERED_CONF_RULES
#else
#if LAYERED_DIVERGECAST
#define LAYERED_RULES { &layered_divergecast }
#else
#define LAYERED_RULES { &layered_multi_channel }
#endif
#endif

/*---------------------------------------------------------------------------*/

#endif /* __LAYERED_CONF_H__ */
