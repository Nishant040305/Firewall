#ifndef __PROTOCOLS_PROTO_IPV4_BPF_H__
#define __PROTOCOLS_PROTO_IPV4_BPF_H__

#include <linux/ip.h>
#include "../core/context.bpf.h"

/* Parse and verify L3 IPv4 Header */
static __always_inline int parse_ipv4(struct pkt_ctx *pkt)
{
    struct iphdr *ip = pkt->iph;
    if ((void *)(ip + 1) > pkt->data_end) {
        return -1;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return -1;
    }

    void *next_hdr = (void *)ip + ip_hdr_len;
    if (next_hdr > pkt->data_end) {
        return -1;
    }

    pkt->iph = ip;
    pkt->l4_hdr = next_hdr;

    /* Populate 5-tuple L3 fields */
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;

    return 0;
}

#endif /* __PROTOCOLS_PROTO_IPV4_BPF_H__ */
