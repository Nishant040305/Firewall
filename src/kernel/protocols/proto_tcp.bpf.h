#ifndef __PROTOCOLS_PROTO_TCP_BPF_H__
#define __PROTOCOLS_PROTO_TCP_BPF_H__

#include <linux/tcp.h>
#include "../core/context.bpf.h"

/* Parse TCP Header and extract ports */
static __always_inline int parse_tcp(struct pkt_ctx *pkt)
{
    struct tcphdr *tcp = (struct tcphdr *)pkt->l4_hdr;
    if ((void *)(tcp + 1) > pkt->data_end) {
        return -1;
    }

    pkt->src_port = tcp->source;
    pkt->dst_port = tcp->dest;
    return 0;
}

#endif /* __PROTOCOLS_PROTO_TCP_BPF_H__ */
