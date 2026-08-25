#ifndef __PROTOCOLS_PROTO_ETH_BPF_H__
#define __PROTOCOLS_PROTO_ETH_BPF_H__

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include "../core/context.bpf.h"

/* Parse and verify L2 Ethernet Header */
static __always_inline int parse_eth(struct pkt_ctx *pkt)
{
    struct ethhdr *eth = pkt->data;
    if ((void *)(eth + 1) > pkt->data_end) {
        return -1;
    }

    pkt->eth = eth;
    pkt->eth_proto = bpf_ntohs(eth->h_proto);
    pkt->iph = (void *)(eth + 1);
    return 0;
}

#endif /* __PROTOCOLS_PROTO_ETH_BPF_H__ */
