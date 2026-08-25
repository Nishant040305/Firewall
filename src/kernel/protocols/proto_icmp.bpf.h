#ifndef __PROTOCOLS_PROTO_ICMP_BPF_H__
#define __PROTOCOLS_PROTO_ICMP_BPF_H__

#include <linux/icmp.h>
#include "../core/context.bpf.h"

/* Parse ICMP Header (ports are 0) */
static __always_inline int parse_icmp(struct pkt_ctx *pkt)
{
    struct icmphdr *icmp = (struct icmphdr *)pkt->l4_hdr;
    if ((void *)(icmp + 1) > pkt->data_end) {
        return -1;
    }

    pkt->src_port = 0;
    pkt->dst_port = 0;
    return 0;
}

#endif /* __PROTOCOLS_PROTO_ICMP_BPF_H__ */
