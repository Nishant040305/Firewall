#ifndef __CORE_RULES_H__
#define __CORE_RULES_H__

#include <linux/types.h>
#include "constants.h"

/* 5-Tuple Firewall Rule Definition */
struct fw_rule {
    __u32 flags;        /* RULE_FLAG_* (active, proto, ip, port checks) */
    __u32 action;       /* ACTION_PASS, ACTION_DROP, ACTION_REJECT */
    __u32 src_ip;       /* Network byte order */
    __u32 src_mask;     /* CIDR subnet mask */
    __u32 dst_ip;       /* Network byte order */
    __u32 dst_mask;     /* CIDR subnet mask */
    __u16 src_port_min; /* Host byte order */
    __u16 src_port_max;
    __u16 dst_port_min;
    __u16 dst_port_max;
    __u8  proto;        /* PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ANY */
    __u8  pad[3];
    __u64 hit_count;    /* Matched packet count */
    __u64 byte_count;   /* Matched byte count */
    char  description[32];
};

#endif /* __CORE_RULES_H__ */
