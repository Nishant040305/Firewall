#ifndef __PROTOCOLS_PROTO_UDP_BPF_H__
#define __PROTOCOLS_PROTO_UDP_BPF_H__

#include <linux/udp.h>
#include "../core/context.bpf.h"

/* Parse UDP Header and extract ports */
static __always_inline int parse_udp(struct pkt_ctx *pkt)
{
    struct udphdr *udp = (struct udphdr *)pkt->l4_hdr;
    if ((void *)(udp + 1) > pkt->data_end) {
        return -1;
    }

    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    return 0;
}

#endif /* __PROTOCOLS_PROTO_UDP_BPF_H__ */
