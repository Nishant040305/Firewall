#ifndef __CORE_TYPES_H__
#define __CORE_TYPES_H__

#include <linux/types.h>
#include "constants.h"
#include "stats.h"

/* Direction of packet capture */
enum packet_direction {
    DIR_UNKNOWN = 0,
    DIR_INGRESS = 1,
    DIR_EGRESS  = 2,
};

/* 5-Tuple Telemetry Event sent to Userspace via BPF RingBuffer */
struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  direction; /* DIR_INGRESS (1) or DIR_EGRESS (2) */
    __u8  pad[2];
    __u32 pkt_len;
};

#endif /* __CORE_TYPES_H__ */
