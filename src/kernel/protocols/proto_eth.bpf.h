#ifndef __PROTOCOLS_PROTO_ETH_BPF_H__
#define __PROTOCOLS_PROTO_ETH_BPF_H__

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include "../core/context.bpf.h"

/* Parse and verify L2 Ethernet Header with aligned 16-bit halfword load */
static __always_inline int parse_eth(struct pkt_ctx *pkt)
{
    void *data = pkt->data;
    if (data + sizeof(struct ethhdr) > pkt->data_end) {
        return -1;
    }

    /* Direct 16-bit halfword load at offset 12 in network byte order */
    __be16 eth_proto = *(__be16 *)(data + 12);
    pkt->eth_proto = bpf_ntohs(eth_proto);
    return 0;
}

#endif /* __PROTOCOLS_PROTO_ETH_BPF_H__ */
