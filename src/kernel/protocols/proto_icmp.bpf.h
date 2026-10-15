#ifndef __PROTOCOLS_PROTO_ICMP_BPF_H__
#define __PROTOCOLS_PROTO_ICMP_BPF_H__

#include <linux/icmp.h>
#include "../core/context.bpf.h"

/* Parse ICMP Header (ports are 0) */
static __always_inline int parse_icmp(struct pkt_ctx *pkt)
{
    struct icmphdr *icmp = (struct icmphdr *)pkt->l4_hdr;
    if ((void *)(icmp + 1) > pkt->data_end || (void *)(icmp + 1) > pkt->l3_end) {
        return -1;
    }

    pkt->src_port = 0;
    pkt->dst_port = 0;
    pkt->tcp_flags = 0;
    pkt->icmp_type = icmp->type;
    pkt->icmp_code = icmp->code;
    return 0;
}

/* Only link-local ND control traffic bypasses policy, never echo or errors.
 * Minimum fixed message sizes and RFC 4861 hop-limit/code are enforced.
 * Redirects are deliberately not exempt. Checksums remain host-validated. */
static __always_inline int valid_neighbor_discovery(const struct pkt_ctx *pkt)
{
    if (pkt->family != FW_AF_INET6 || pkt->hop_limit != 255 || pkt->icmp_code)
        return 0;
    __u32 size;
    switch (pkt->icmp_type) {
    case 133: size = 8; break;
    case 134: size = 16; break;
    case 135: case 136: size = 24; break;
    default: return 0;
    }
    /* Router advertisements must originate from a link-local address. */
    if (pkt->icmp_type == 134 &&
        (bpf_ntohl(pkt->src_ip6.words[0]) & 0xffc00000u) != 0xfe800000u)
        return 0;
    return pkt->l4_hdr + size <= pkt->data_end && pkt->l4_hdr + size <= pkt->l3_end;
}

#endif /* __PROTOCOLS_PROTO_ICMP_BPF_H__ */
