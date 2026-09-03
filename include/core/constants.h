#ifndef __CORE_CONSTANTS_H__
#define __CORE_CONSTANTS_H__

#include <linux/types.h>

/* Capacity Limits */
#define MAX_FLOW_ENTRIES       65536
#define MAX_RULE_ENTRIES       128
#define RINGBUF_EVENT_SIZE     (1 << 16) /* 64KB RingBuffer */

/* IP Protocols */
#define PROTO_ANY  0
#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

/* Rule Actions */
#define ACTION_PASS   1
#define ACTION_DROP   2
#define ACTION_REJECT 3

/* Rule Matching Flags */
#define RULE_FLAG_ACTIVE       (1 << 0)
#define RULE_FLAG_SRC_IP       (1 << 1)
#define RULE_FLAG_DST_IP       (1 << 2)
#define RULE_FLAG_SRC_PORT     (1 << 3)
#define RULE_FLAG_DST_PORT     (1 << 4)
#define RULE_FLAG_PROTO        (1 << 5)

/* Timeouts (Nanoseconds) */
#define UDP_TIMEOUT_NS             (30ULL * 1000000000ULL)  /* 30 seconds */
#define ICMP_TIMEOUT_NS            (10ULL * 1000000000ULL)  /* 10 seconds */
#define TCP_SYN_TIMEOUT_NS         (30ULL * 1000000000ULL)  /* 30 seconds */
#define TCP_ESTABLISHED_TIMEOUT_NS (300ULL * 1000000000ULL) /* 5 minutes */
#define TCP_CLOSE_TIMEOUT_NS       (10ULL * 1000000000ULL)  /* 10 seconds */

/* Default BPF Map Pin Paths */
#define BPF_FS_PATH                "/sys/fs/bpf/firewall"
#define MAP_PIN_RULES              "/sys/fs/bpf/firewall/rules_map"
#define MAP_PIN_CONNTRACK          "/sys/fs/bpf/firewall/conntrack_map"
#define MAP_PIN_STATS              "/sys/fs/bpf/firewall/stats_map"
#define MAP_PIN_EVENTS             "/sys/fs/bpf/firewall/events_ringbuf"

#endif /* __CORE_CONSTANTS_H__ */
