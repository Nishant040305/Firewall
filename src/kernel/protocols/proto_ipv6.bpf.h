#ifndef __PROTOCOLS_PROTO_IPV6_BPF_H__
#define __PROTOCOLS_PROTO_IPV6_BPF_H__

#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include "../core/context.bpf.h"

/* Bounded extension walk. Fragments, ESP, jumbograms and overlong chains
 * are rejected: this dataplane has neither reassembly nor decryption. */
static __always_inline int parse_ipv6(struct pkt_ctx *pkt)
{
    struct ipv6hdr *ip = pkt->data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > pkt->data_end || ip->version != 6)
        return -1;
    __u32 len = bpf_ntohs(ip->payload_len);
    /* Older verifiers lose scalar bounds after endian conversion. */
    asm volatile("%0 &= 65535" : "+r"(len));
    void *end = (void *)(ip + 1) + len;
    if (!len || end > pkt->data_end)
        return -1;
    pkt->l3_end = end;
    pkt->family = FW_AF_INET6;
    pkt->src_ip = 0;
    pkt->dst_ip = 0;
    __builtin_memcpy(&pkt->src_ip6, &ip->saddr, 16);
    __builtin_memcpy(&pkt->dst_ip6, &ip->daddr, 16);
    pkt->hop_limit = ip->hop_limit;
    __u8 next = ip->nexthdr;
    void *cursor = ip + 1;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (next == 44 || next == 50) /* Fragment / ESP */
            return -1;
        if (next != 0 && next != 43 && next != 60 && next != 51) {
            pkt->proto = next;
            pkt->flow.proto = next;
            pkt->l4_hdr = cursor;
            return 0;
        }
        __u8 *ext = cursor;
        if ((void *)(ext + 2) > pkt->data_end || (void *)(ext + 2) > end)
            return -1;
        /* Hop-by-hop is valid only immediately after the base header. */
        if (next == 0 && i != 0)
            return -1;
        __u32 size = next == 51 ? ((__u32)ext[1] + 2) * 4 : ((__u32)ext[1] + 1) * 8;
        if (size < 8 || cursor + size > pkt->data_end || cursor + size > end)
            return -1;
        next = ext[0];
        cursor += size;
    }
    return -1;
}

#endif
