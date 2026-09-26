#ifndef __PROTOCOLS_PROTO_TCP_BPF_H__
#define __PROTOCOLS_PROTO_TCP_BPF_H__

#include <linux/tcp.h>
#include "../core/context.bpf.h"

/* Parse TCP Header, extract ports with single 32-bit load and extract flags */
static __always_inline int parse_tcp(struct pkt_ctx *pkt)
{
    struct tcphdr *tcp = (struct tcphdr *)pkt->l4_hdr;
    if ((void *)(tcp + 1) > pkt->data_end) {
        return -1;
    }

    /* Single 32-bit load reads both source and destination ports simultaneously */
    __u32 ports = *(__u32 *)tcp;
    pkt->src_port = (__u16)ports;
    pkt->dst_port = (__u16)(ports >> 16);
    pkt->tcp_flags = *((__u8 *)tcp + 13);
    return 0;
}

#endif /* __PROTOCOLS_PROTO_TCP_BPF_H__ */
