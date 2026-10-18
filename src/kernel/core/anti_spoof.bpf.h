#ifndef __CORE_ANTI_SPOOF_BPF_H__
#define __CORE_ANTI_SPOOF_BPF_H__
#include <core/anti_spoof.h>
#include "context.bpf.h"
#include "maps.bpf.h"
#include "helpers.bpf.h"

static __always_inline int anti_spoof_allow(struct pkt_ctx *pkt)
{
    if (pkt->direction != DIR_INGRESS)
        return 1;
    __u32 scope = pkt->ifindex;
    if (!bpf_map_lookup_elem(&anti_spoof_scopes, &scope))
        return 1;
    struct anti_spoof_key key = {
        .prefixlen = ANTI_SPOOF_SCOPE_BITS + 32,
        .ifindex = scope, .family = pkt->family,
    };
    if (pkt->family == FW_AF_INET6) {
        key.prefixlen = ANTI_SPOOF_SCOPE_BITS + 128;
        __builtin_memcpy(key.address, pkt->src_ip6.words, sizeof(key.address));
    } else {
        key.address[0] = pkt->src_ip;
    }
    __u32 *allow = bpf_map_lookup_elem(&anti_spoof_prefix, &key);
    if (allow && *allow == 1)
        return 1;
    pkt->reason = REASON_ANTI_SPOOF;
    inc_stat(STAT_ANTI_SPOOF_DROP);
    return 0;
}
#endif
