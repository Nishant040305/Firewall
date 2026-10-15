#include <assert.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <core/constants.h>

static int pull_calls;
static int pull_result;
static long mock_pull_data(struct __sk_buff *skb, __u32 len)
{
    pull_calls++;
    assert(len == skb->len);
    if (pull_result)
        return pull_result;
    /* Model a helper relocating the packet while making it linear. */
    skb->data = 8192;
    skb->data_end = skb->data + len;
    return 0;
}

#define bpf_skb_pull_data mock_pull_data
#include "core/context.bpf.h"
#undef bpf_skb_pull_data

int main(void)
{
    struct pkt_ctx pkt;
    struct __sk_buff skb = {.data = 4096, .data_end = 4196, .len = 100};
    assert(!pkt_ctx_init_skb(&pkt, &skb, DIR_EGRESS));
    assert(!pull_calls);
    assert(pkt.data == (void *)4096 && pkt.data_end == (void *)4196);

    skb.data_end = skb.data + 54; /* Headers linear, payload fragmented. */
    assert(!pkt_ctx_init_skb(&pkt, &skb, DIR_EGRESS));
    assert(pull_calls == 1);
    assert(pkt.data == (void *)8192 && pkt.data_end == (void *)8292);
    assert(pkt.pkt_len == 100 && pkt.direction == DIR_EGRESS);

    skb.data_end = skb.data + 54;
    assert(!pkt_ctx_init_skb(&pkt, &skb, DIR_INGRESS));
    assert(pull_calls == 2 && pkt.direction == DIR_INGRESS);

    pull_result = -1;
    skb.data_end = skb.data + 54;
    assert(pkt_ctx_init_skb(&pkt, &skb, DIR_EGRESS) < 0);
    assert(pull_calls == 3);

    skb = (struct __sk_buff){.data = 4096, .data_end = 4100, .len = 4};
    assert(pkt_ctx_init_skb(&pkt, &skb, DIR_EGRESS) < 0);
    assert(pull_calls == 3);
    puts("TC linear/non-linear context and pull failure tests passed");
    return 0;
}
