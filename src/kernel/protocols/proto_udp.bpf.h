#ifndef __PROTOCOLS_PROTO_UDP_BPF_H__
#define __PROTOCOLS_PROTO_UDP_BPF_H__

#include <linux/udp.h>
#include "../core/context.bpf.h"

/* Validate UDP length and extract network-order ports. */
static __always_inline int parse_udp(struct pkt_ctx *pkt)
{
    struct udphdr *udp = (struct udphdr *)pkt->l4_hdr;
    if ((void *)(udp + 1) > pkt->data_end || (void *)(udp + 1) > pkt->l3_end) {
        return -1;
    }

    __u32 len = bpf_ntohs(udp->len);
    if (len < sizeof(*udp) || (void *)udp + len > pkt->data_end || (void *)udp + len > pkt->l3_end)
        return -1;
    if (pkt->family == FW_AF_INET6 && !udp->check)
        return -1;
    pkt->src_port = udp->source;
    pkt->dst_port = udp->dest;
    pkt->tcp_flags = 0;
    return 0;
}

#endif /* __PROTOCOLS_PROTO_UDP_BPF_H__ */
