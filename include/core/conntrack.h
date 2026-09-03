#ifndef __CORE_CONNTRACK_H__
#define __CORE_CONNTRACK_H__

#include <linux/types.h>
#include "constants.h"

/* Connection States */
enum conn_state {
    CONN_STATE_INVALID = 0,
    CONN_STATE_NEW,            /* Initial packet evaluated by rule */
    CONN_STATE_SYN_SENT,       /* Client sent SYN */
    CONN_STATE_SYN_RECV,       /* Server sent SYN-ACK */
    CONN_STATE_ESTABLISHED,    /* Handshake complete / active session */
    CONN_STATE_FIN_WAIT,       /* FIN sent from one party */
    CONN_STATE_CLOSE_WAIT,     /* FIN acknowledged */
    CONN_STATE_CLOSED,         /* RST or fully closed */
    CONN_STATE_UDP_ACTIVE,     /* Active UDP session */
    CONN_STATE_ICMP_ACTIVE,    /* Active ICMP Echo session */
};

/* 5-Tuple Connection Key */
struct flow_key {
    __u32 src_ip;    /* Network byte order */
    __u32 dst_ip;    /* Network byte order */
    __u16 src_port;  /* Network byte order */
    __u16 dst_port;  /* Network byte order */
    __u8  proto;     /* IP protocol number */
    __u8  pad[3];
};

/* Stateful Connection Value */
struct flow_entry {
    __u32 state;            /* enum conn_state */
    __u32 flags_seen;       /* Observed TCP flags */
    __u64 created_ns;       /* Start timestamp (nanoseconds) */
    __u64 last_seen_ns;     /* Most recent packet timestamp */
    __u64 packets_forward;  /* Packets client -> server */
    __u64 packets_reverse;  /* Packets server -> client */
    __u64 bytes_forward;    /* Bytes client -> server */
    __u64 bytes_reverse;    /* Bytes server -> client */
    __u64 timeout_ns;       /* Timeout duration */
};

#endif /* __CORE_CONNTRACK_H__ */
