#ifndef __CORE_CONTEXT_BPF_H__
#define __CORE_CONTEXT_BPF_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <core/types.h>

/* Unified Packet Processing Context */
struct pkt_ctx {
    void *data;
    void *data_end;
    __u32 pkt_len;
    __u16 eth_proto;
    __u8  direction;
    __u8  proto;
    struct ethhdr *eth;
    struct iphdr  *iph;
    void *l4_hdr;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  tcp_flags;
    __u8  action;
    __u8  conn_state;
    __u32 rule_id;
};

/* Initialize packet context from raw XDP metadata (Ingress only) */
static __always_inline int pkt_ctx_init_xdp(struct pkt_ctx *pctx, struct xdp_md *ctx)
{
    pctx->data = (void *)(long)ctx->data;
    pctx->data_end = (void *)(long)ctx->data_end;
    pctx->pkt_len = (__u32)(pctx->data_end - pctx->data);
    pctx->direction = DIR_INGRESS;
    pctx->eth_proto = 0;
    pctx->proto = 0;
    pctx->eth = NULL;
    pctx->iph = NULL;
    pctx->l4_hdr = NULL;
    pctx->src_ip = 0;
    pctx->dst_ip = 0;
    pctx->src_port = 0;
    pctx->dst_port = 0;
    pctx->tcp_flags = 0;
    pctx->action = ACTION_PASS;
    pctx->conn_state = CONN_STATE_INVALID;
    pctx->rule_id = 0;

    if (pctx->data + sizeof(struct ethhdr) > pctx->data_end) {
        return -1;
    }
    return 0;
}

/* Backward-compatibility alias */
static __always_inline int pkt_ctx_init(struct pkt_ctx *pctx, struct xdp_md *ctx)
{
    return pkt_ctx_init_xdp(pctx, ctx);
}

/* Initialize packet context from TC __sk_buff (Ingress or Egress) */
static __always_inline int pkt_ctx_init_skb(struct pkt_ctx *pctx, struct __sk_buff *skb, __u8 direction)
{
    pctx->data = (void *)(long)skb->data;
    pctx->data_end = (void *)(long)skb->data_end;
    pctx->pkt_len = skb->len;
    pctx->direction = direction;
    pctx->eth_proto = 0;
    pctx->proto = 0;
    pctx->eth = NULL;
    pctx->iph = NULL;
    pctx->l4_hdr = NULL;
    pctx->src_ip = 0;
    pctx->dst_ip = 0;
    pctx->src_port = 0;
    pctx->dst_port = 0;
    pctx->tcp_flags = 0;
    pctx->action = ACTION_PASS;
    pctx->conn_state = CONN_STATE_INVALID;
    pctx->rule_id = 0;

    if (pctx->data + sizeof(struct ethhdr) > pctx->data_end) {
        return -1;
    }
    return 0;
}

#endif /* __CORE_CONTEXT_BPF_H__ */
