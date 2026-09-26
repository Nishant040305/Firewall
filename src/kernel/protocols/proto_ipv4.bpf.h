#ifndef __PROTOCOLS_PROTO_IPV4_BPF_H__
#define __PROTOCOLS_PROTO_IPV4_BPF_H__

#include <linux/if_ether.h>
#include <linux/ip.h>
#include "../core/context.bpf.h"

/* Parse and verify L3 IPv4 Header with fast-path IHL==5 specialization */
static __always_inline int parse_ipv4(struct pkt_ctx *pkt)
{
    void *data = pkt->data;
    void *data_end = pkt->data_end;

    /* Combined check: Ethernet (14) + Base IPv4 (20) = 34 bytes */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return -1;
    }

    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));

    /* Basic IPv4 sanity check */
    if (ip->version != 4) {
        return -1;
    }

    void *next_hdr;
    /* Fast path: IHL == 5 (No IP options - 99.9% of traffic) */
    if (__builtin_expect(ip->ihl == 5, 1)) {
        next_hdr = (void *)(ip + 1);
    } else {
        __u32 ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr)) {
            return -1;
        }
        next_hdr = (void *)ip + ip_hdr_len;
        if (next_hdr > data_end) {
            return -1;
        }
    }

    pkt->l4_hdr = next_hdr;

    /* Populate 5-tuple L3 fields directly into context and flow key */
    pkt->src_ip = ip->saddr;
    pkt->dst_ip = ip->daddr;
    pkt->proto = ip->protocol;
    pkt->flow.proto = ip->protocol;

    return 0;
}

#endif /* __PROTOCOLS_PROTO_IPV4_BPF_H__ */
