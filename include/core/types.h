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

/* Operation Step Indices for Detailed Timing & Latency Analysis */
enum op_step {
    STEP_EXTRACTION = 0,      /* Header parsing & 5-tuple extraction (L2, L3, L4) */
    STEP_HASH_CAL,            /* Flow key generation and 5-tuple hash calculation */
    STEP_LOOKUP_CACHE,        /* L1 per-CPU direct-indexed flow cache lookup */
    STEP_LOOKUP_CONNTRACK,    /* Conntrack state table lookup */
    STEP_LOOKUP_RULES,        /* Policy rule engine lookup & matching */
    STEP_LOOKUP_TOTAL,        /* Total lookup time (Cache + Conntrack + Rules) */
    STEP_UPDATE_CONNTRACK,    /* State table update / insertion / deletion */
    STEP_UPDATE_STATS,        /* Statistics per-CPU counter increments */
    STEP_UPDATE_RINGBUF,      /* Telemetry ring buffer event submission */
    STEP_UPDATE_TOTAL,        /* Total update time (Conntrack + Stats + Telemetry) */
    STEP_TOTAL_PIPELINE,      /* Total end-to-end packet processing duration */
    STEP_MAX_OPS,
};

/* Timing Metric Accumulator for BPF Telemetry */
struct step_metric {
    __u64 total_time_ns;
    __u64 count;
    __u64 min_time_ns;
    __u64 max_time_ns;
};

/* 5-Tuple Telemetry Event sent to Userspace via BPF RingBuffer */
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
    __u8  pad[3];

    /* Per-packet execution timing checks (nanoseconds) */
    __u32 time_extract_ns; /* L2/L3/L4 Header Extraction */
    __u32 time_hash_ns;    /* Flow key and hash computation */
    __u32 time_lookup_ns;  /* State table & rule lookup */
    __u32 time_update_ns;  /* State, stats & ringbuf update */
    __u32 time_total_ns;   /* Full packet traversal latency */
};

#endif /* __CORE_TYPES_H__ */
