#ifndef __CORE_TYPES_H__
#define __CORE_TYPES_H__

#include <linux/types.h>
#include "constants.h"
#include "stats.h"
#include "rules.h"
#include "conntrack.h"

/* Direction of packet capture */
enum packet_direction {
    DIR_UNKNOWN = 0,
    DIR_INGRESS = 1,
    DIR_EGRESS  = 2,
};

enum event_reason {
    REASON_STATE = 0,
    REASON_POLICY = 1,
    REASON_DEFAULT_POLICY = 2,
    REASON_INVALID_STATE = 3,
    REASON_MALFORMED = 4,
    REASON_RATE_LIMIT = 5,
    REASON_ANTI_SPOOF = 6,
    REASON_CONN_LIMIT = 7,
};

#if FW_TIMING
/* Stable metric IDs across engines. Hash/cache metrics are FastCache-only. */
enum op_step {
    STEP_EXTRACTION, STEP_HASH_CAL, STEP_LOOKUP_CACHE,
    STEP_LOOKUP_CONNTRACK, STEP_LOOKUP_RULES, STEP_LOOKUP_TOTAL,
    STEP_UPDATE_CONNTRACK, STEP_UPDATE_STATS, STEP_UPDATE_RINGBUF,
    STEP_UPDATE_TOTAL, STEP_TOTAL_PIPELINE, STEP_MAX_OPS,
};
struct step_metric {
    __u64 total_time_ns, count, min_time_ns, max_time_ns;
};
#endif

/* Metadata only: no application payloads or credentials. */
struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction;    /* DIR_INGRESS (1) or DIR_EGRESS (2) */
    __u8  action;       /* ACTION_PASS, ACTION_DROP */
    __u8  conn_state;   /* enum conn_state */
    __u32 rule_id;      /* Matching rule ID or 0 */
    __u32 pkt_len;
    __u8  tcp_flags;
    __u8  reason;
    __u8  new_flow;
    __u8  pad;
    __u32 ifindex;
    struct ip6_addr src_ip6;
    struct ip6_addr dst_ip6;
    __u8 family;
    __u8 family_pad[7];
};

#endif /* __CORE_TYPES_H__ */
