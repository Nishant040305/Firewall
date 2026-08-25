#ifndef __CORE_CONSTANTS_H__
#define __CORE_CONSTANTS_H__

#include <linux/types.h>

/* Capacity Limits */
#define MAX_FLOW_ENTRIES       65536
#define MAX_RULE_ENTRIES       1024
#define RINGBUF_EVENT_SIZE     (1 << 16) /* 64KB RingBuffer */

/* Protocols */
#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

/* Timeouts */
#define UDP_TIMEOUT_NS             (30ULL * 1000000000ULL)  /* 30 seconds */
#define TCP_SYN_TIMEOUT_NS         (30ULL * 1000000000ULL)  /* 30 seconds */
#define TCP_ESTABLISHED_TIMEOUT_NS (300ULL * 1000000000ULL) /* 5 minutes */

#endif /* __CORE_CONSTANTS_H__ */
