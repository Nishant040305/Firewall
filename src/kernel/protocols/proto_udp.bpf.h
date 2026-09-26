#ifndef __PROTOCOLS_PROTO_UDP_BPF_H__
#define __PROTOCOLS_PROTO_UDP_BPF_H__

#include <linux/udp.h>
#include "../core/context.bpf.h"

/* Parse UDP Header and extract ports with single 32-bit load */
static __always_inline int parse_udp(struct pkt_ctx *pkt)
{
    struct udphdr *udp = (struct udphdr *)pkt->l4_hdr;
    if ((void *)(udp + 1) > pkt->data_end) {
        return -1;
    }

    /* Single 32-bit load reads both source and destination ports simultaneously */
    __u32 ports = *(__u32 *)udp;
    pkt->src_port = (__u16)ports;
    pkt->dst_port = (__u16)(ports >> 16);
    pkt->tcp_flags = 0;
    return 0;
}

#endif /* __PROTOCOLS_PROTO_UDP_BPF_H__ */
