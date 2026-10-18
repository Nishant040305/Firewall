#include <assert.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <core/types.h>
#if FW_CONN_LIMIT
#include <core/connection_limit.h>
#endif
#if FW_ANTI_SPOOF
#include <core/anti_spoof.h>
#endif
#if FW_RATE_LIMIT
#include <core/rate_limit.h>
#endif
#include "utils/ip_utils.h"
#include "core/cli.h"
#include "core/rules_mgr.h"

static void unit_tests(void)
{
    struct fw_rule r = {0};
    assert(!rule_set_address(&r, "2001:db8:abcd::1/48", 1));
    assert(r.family == FW_AF_INET6);
    assert(ntohl(r.src_mask6.words[0]) == 0xffffffffu);
    assert(ntohl(r.src_mask6.words[1]) == 0xffff0000u);
    assert(!r.src_mask6.words[2]);
    assert(rule_set_address(&r, "10.0.0.1", 0) < 0);
    assert(rule_set_address(&r, "::/129", 0) < 0);
    assert(rule_set_address(&r, "::/no", 0) < 0);
    assert(rule_set_address(&r, "not-an-ip", 0) < 0);
    assert(!rule_set_address(&r, "::/0", 0));
    r = (struct fw_rule){0};
    assert(!rule_set_address(&r, "192.0.2.1/24", 0));
    assert(ntohl(r.dst_mask) == 0xffffff00u);
    assert(rule_set_address(&r, "192.0.2.1/33", 0) < 0);
    __u16 min, max;
    assert(!parse_port_range("80-443", &min, &max) && min == 80 && max == 443);
    assert(parse_port_range("443-80", &min, &max) < 0);
    assert(parse_port_range("65536", &min, &max) < 0);
    assert(parse_port_range("80junk", &min, &max) < 0);
    char *args[] = {"fw-ctl", "rule", "add", "--proto", "tcp", "--dst",
                    "fd10:10:2::10/128", "--dport", "80", "--sport", "1024-65535"};
    struct firewall_options opts;
    assert(!parse_cli_args(sizeof(args) / sizeof(*args), args, &opts));
    assert(opts.new_rule.family == FW_AF_INET6);
    assert(opts.new_rule.flags & RULE_FLAG_DST_PORT);
    assert(opts.new_rule.flags & RULE_FLAG_SRC_PORT);
    char *bad_action[] = {"fw-ctl", "rule", "add", "--action", "alow"};
    assert(parse_cli_args(5, bad_action, &opts) < 0);
#if FW_TIMING
    char *perf_args[] = {"fw-ctl", "perf", "show", "--json"};
    assert(!parse_cli_args(4, perf_args, &opts));
    assert(opts.cmd == CMD_PERF_SHOW && opts.json_output);
#endif
    puts("IPv4/IPv6 address, CIDR and CLI tests passed");
}

static unsigned char frame[256];
static size_t packet(int family, int proto, int reverse, int flags, int port)
{
    memset(frame, 0, sizeof(frame));
    struct ethhdr *eth = (void *)frame;
    eth->h_proto = htons(family == 6 ? ETH_P_IPV6 : ETH_P_IP);
    size_t off = sizeof(*eth), l4 = proto == IPPROTO_TCP ? 20 : 8;
    if (family == 6) {
        struct ipv6hdr *ip = (void *)(frame + off);
        ip->version = 6;
        ip->nexthdr = proto;
        ip->hop_limit = 64;
        ip->payload_len = htons(l4);
        inet_pton(AF_INET6, reverse ? "fd10:10:2::10" : "fd10:10:1::20", &ip->saddr);
        inet_pton(AF_INET6, reverse ? "fd10:10:1::20" : "fd10:10:2::10", &ip->daddr);
        off += sizeof(*ip);
    } else {
        struct iphdr *ip = (void *)(frame + off);
        ip->version = 4;
        ip->ihl = 5;
        ip->protocol = proto;
        ip->tot_len = htons(20 + l4);
        ip->saddr = inet_addr(reverse ? "10.10.2.10" : "10.10.1.20");
        ip->daddr = inet_addr(reverse ? "10.10.1.20" : "10.10.2.10");
        off += sizeof(*ip);
    }
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(frame + off);
        tcp->source = htons(reverse ? port : 40000);
        tcp->dest = htons(reverse ? 40000 : port);
        tcp->doff = 5;
        frame[off + 13] = flags;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(frame + off);
        udp->source = htons(reverse ? port : 40000);
        udp->dest = htons(reverse ? 40000 : port);
        udp->len = htons(8);
        udp->check = htons(1);
    } else {
        frame[off] = flags; /* ICMP type */
    }
    return off + l4;
}

static int tests;
static int rate_test_hook = -1;
static __u32 test_ifindex = 1;
static void run(int fd, size_t len, unsigned expected, const char *name)
{
    unsigned char out[512];
    struct xdp_md xdp = {.ingress_ifindex = test_ifindex, .data_end = len};
    struct __sk_buff skb = {.ifindex = test_ifindex};
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = frame, .data_size_in = len,
        .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
    if (rate_test_hook >= 0) {
        opts.ctx_in = rate_test_hook ? (void *)&skb : (void *)&xdp;
        opts.ctx_size_in = rate_test_hook ? sizeof(skb) : sizeof(xdp);
    }
    int err = bpf_prog_test_run_opts(fd, &opts);
    if (err || opts.retval != expected) {
        fprintf(stderr, "FAIL %s: error=%d action=%u expected=%u\n", name, err, opts.retval, expected);
        assert(0);
    }
    tests++;
}

static void dataplane_tests(const char *path)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    assert(!libbpf_get_error(obj));
    assert(!!bpf_object__find_map_by_name(obj, "flow_cache_map") ==
           (FW_ENGINE == FW_ENGINE_FASTCACHE));
    assert(!!bpf_object__find_map_by_name(obj, "ct_syn_map") ==
           (FW_ENGINE == FW_ENGINE_DUALMAP));
    assert(!!bpf_object__find_map_by_name(obj, "perf_map") == !!FW_TIMING);
    assert(!!bpf_object__find_map_by_name(obj, "events_ringbuf") ==
           (FW_OBSERVABILITY == 0));
    assert(!!bpf_object__find_map_by_name(obj, "stats_map") ==
            (FW_OBSERVABILITY != 2));
    assert(!!bpf_object__find_map_by_name(obj, "syn_rate_config") == !!FW_RATE_LIMIT);
    assert(!!bpf_object__find_map_by_name(obj, "syn_rate_total") == !!FW_RATE_LIMIT);
    assert(!!bpf_object__find_map_by_name(obj, "syn_rate_sources") == !!FW_RATE_LIMIT);
    assert(!!bpf_object__find_map_by_name(obj, "anti_spoof_scopes") == !!FW_ANTI_SPOOF);
    assert(!!bpf_object__find_map_by_name(obj, "anti_spoof_prefix") == !!FW_ANTI_SPOOF);
    const char *connection_maps[] = {"conn_limit_cfg", "conn_limit_src", "conn_limit_hint",
                                     "conn_limit_zero", "conn_limit_on", "conn_limit_tmp"};
    for (unsigned i = 0; i < sizeof(connection_maps) / sizeof(connection_maps[0]); i++)
        assert(!!bpf_object__find_map_by_name(obj, connection_maps[i]) == !!FW_CONN_LIMIT);
    assert(!bpf_object__load(obj)); /* Verifies XDP and both TC programs. */
    int fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    int map = bpf_map__fd(bpf_object__find_map_by_name(obj, "rules_map"));
    assert(rules_mgr_load_file(map, "config/rules.yaml") > 0);
    /* The shipped policy ends in a dual-stack catch-all allow rule. */
    int found_catch_all = 0;
    for (__u32 i = 0; i < MAX_RULE_ENTRIES; i++) {
        struct fw_rule loaded;
        assert(!bpf_map_lookup_elem(map, &i, &loaded));
        if ((loaded.flags & RULE_FLAG_ACTIVE) && !loaded.family &&
            loaded.proto == PROTO_ANY && loaded.action == ACTION_PASS &&
            !(loaded.flags & (RULE_FLAG_SRC_IP | RULE_FLAG_DST_IP |
                              RULE_FLAG_SRC_PORT | RULE_FLAG_DST_PORT)))
            found_catch_all = 1;
    }
    assert(found_catch_all);
    assert(!rules_mgr_flush(map));
    struct fw_rule r = {.flags = RULE_FLAG_ACTIVE | RULE_FLAG_PROTO | RULE_FLAG_DST_PORT,
                        .proto = PROTO_TCP, .action = ACTION_PASS,
                        .dst_port_min = 80, .dst_port_max = 80};
    assert(!rule_set_address(&r, "fd10:10:2::/64", 0));
    __u32 key = 0;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    for (int hook = 0; hook < 3; hook++) {
        const char *names[] = {"xdp_firewall_prog", "tc_ingress_prog", "tc_egress_prog"};
        fd = bpf_program__fd(bpf_object__find_program_by_name(obj, names[hook]));
        unsigned pass = hook ? 0 : 2, drop = hook ? 2 : 1;
        run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), pass, "IPv6 allowed SYN");
        run(fd, packet(6, IPPROTO_TCP, 1, 18, 80), pass, "IPv6 reverse SYN-ACK");
        run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), pass, "IPv6 established ACK");
        run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), pass, "IPv6 fast cache hit");
        run(fd, packet(4, IPPROTO_TCP, 0, 16, 80), drop, "IPv4 cannot reuse IPv6 state");
        run(fd, packet(6, IPPROTO_TCP, 0, 2, 8080), drop, "IPv6 blocked port");
        run(fd, packet(6, IPPROTO_TCP, 0, 16, 8080), drop, "IPv6 unsolicited ACK");
        size_t len = packet(6, IPPROTO_TCP, 0, 2, 80);
        ((struct ipv6hdr *)(frame + 14))->daddr.s6_addr[7] = 3;
        run(fd, len, drop, "IPv6 CIDR mismatch");
        len = packet(6, IPPROTO_TCP, 0, 2, 80);
        struct ipv6hdr *ip = (void *)(frame + 14);
        memmove(frame + 62, frame + 54, 20);
        frame[54] = IPPROTO_TCP;
        memset(frame + 55, 0, 7);
        ip->nexthdr = 60;
        ip->payload_len = htons(28);
        run(fd, len + 8, pass, "IPv6 destination options");
        ip->nexthdr = 44;
        run(fd, len + 8, drop, "IPv6 fragments rejected");
        run(fd, packet(6, IPPROTO_TCP, 0, 2, 80) - 1, drop, "truncated IPv6");
        len = packet(6, IPPROTO_ICMPV6, 0, 135, 0);
        ip = (void *)(frame + 14);
        ip->hop_limit = 255;
        ip->payload_len = htons(24);
        run(fd, len + 16, pass, "Neighbor Solicitation");
        ip->hop_limit = 64;
        run(fd, len + 16, drop, "invalid ND hop limit");
        len = packet(6, IPPROTO_ICMPV6, 0, 134, 0);
        ip->hop_limit = 255;
        ip->payload_len = htons(16);
        run(fd, len + 8, drop, "non-link-local Router Advertisement");
    }
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    r = (struct fw_rule){.flags = RULE_FLAG_ACTIVE | RULE_FLAG_PROTO | RULE_FLAG_DST_PORT,
                         .proto = PROTO_UDP, .action = ACTION_PASS,
                         .dst_port_min = 5201, .dst_port_max = 5201};
    assert(!rule_set_address(&r, "fd10:10:2::10", 0));
    key = 1;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    run(fd, packet(6, IPPROTO_UDP, 0, 0, 5201), 2, "IPv6 UDP new flow");
    run(fd, packet(6, IPPROTO_UDP, 1, 0, 5201), 2, "IPv6 UDP reverse flow");
    run(fd, packet(6, IPPROTO_UDP, 0, 0, 5201), 2, "IPv6 UDP cache hit");
    size_t len = packet(6, IPPROTO_UDP, 0, 0, 5201);
    ((struct udphdr *)(frame + 54))->check = 0;
    run(fd, len, 1, "IPv6 zero UDP checksum");
    r = (struct fw_rule){.flags = RULE_FLAG_ACTIVE | RULE_FLAG_PROTO,
                         .proto = PROTO_ICMPV6, .action = ACTION_PASS};
    key = 2;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    run(fd, packet(6, IPPROTO_ICMPV6, 0, 128, 0), 2, "IPv6 echo request");
    run(fd, packet(6, IPPROTO_ICMPV6, 1, 129, 0), 2, "IPv6 echo reply");
    r = (struct fw_rule){.flags = RULE_FLAG_ACTIVE | RULE_FLAG_PROTO | RULE_FLAG_DST_PORT,
                         .proto = PROTO_TCP, .action = ACTION_PASS,
                         .dst_port_min = 80, .dst_port_max = 80};
    assert(!rule_set_address(&r, "10.10.2.0/24", 0));
    key = 3;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 2, "IPv4 allowed SYN regression");
    len = packet(4, IPPROTO_TCP, 0, 2, 80);
    ((struct iphdr *)(frame + 14))->frag_off = htons(0x2000);
    run(fd, len, 1, "IPv4 fragment regression");
    r = (struct fw_rule){.flags = RULE_FLAG_ACTIVE | RULE_FLAG_PROTO | RULE_FLAG_DST_PORT,
                         .proto = PROTO_TCP, .action = ACTION_PASS,
                         .dst_port_min = 443, .dst_port_max = 443};
    assert(!rule_set_address(&r, "fd10:10:2::/64", 0));
    key = MAX_RULE_ENTRIES - 1;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 443), 2, "last rule slot evaluated");
    len = packet(6, IPPROTO_TCP, 0, 2, 443);
    ((struct ipv6hdr *)(frame + 14))->payload_len = htons(8);
    run(fd, len, 1, "Ethernet padding cannot supply transport header");
    len = packet(6, IPPROTO_TCP, 0, 2, 443);
    ((struct tcphdr *)(frame + 54))->doff = 4;
    run(fd, len, 1, "invalid TCP data offset");
    len = packet(6, IPPROTO_UDP, 0, 0, 5201);
    ((struct udphdr *)(frame + 54))->len = htons(7);
    run(fd, len, 1, "invalid UDP length");
    /* An echo session must not authorize an otherwise denied ICMPv6 error. */
    r = (struct fw_rule){0};
    key = 2;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    run(fd, packet(6, IPPROTO_ICMPV6, 0, 2, 0), 1, "ICMPv6 error does not reuse echo state");
#if FW_RATE_LIMIT
    /* Test-run contexts explicitly select loopback's ifindex; no attachment. */
    rate_test_hook = 0;
    int rate_cfg = bpf_object__find_map_fd_by_name(obj, "syn_rate_config");
    int rate_total = bpf_object__find_map_fd_by_name(obj, "syn_rate_total");
    int rate_sources = bpf_object__find_map_fd_by_name(obj, "syn_rate_sources");
    struct syn_rate_config limits = {1, 2, 1, 100, 1};
    struct rate_bucket bucket = {.last_refill_ns = ~0ULL,
        .credit = 100 * RATE_CREDIT_PER_PACKET};
    key = 1;
    assert(!bpf_map_update_elem(rate_total, &key, &bucket, BPF_ANY));
    assert(!bpf_map_update_elem(rate_cfg, &key, &limits, BPF_ANY));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 2, "SYN source burst first packet");
    struct rate_source_key source_key = {.ifindex = 1, .family = FW_AF_INET6};
    inet_pton(AF_INET6, "fd10:10:1::20", source_key.address);
    assert(!bpf_map_lookup_elem_flags(rate_sources, &source_key, &bucket, BPF_F_LOCK));
    bucket.last_refill_ns = ~0ULL; /* Freeze refill for deterministic tests. */
    assert(!bpf_map_update_elem(rate_sources, &source_key, &bucket, BPF_EXIST | BPF_F_LOCK));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 2, "SYN source burst second packet");
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 1, "SYN source exhaustion drops");
    run(fd, packet(6, IPPROTO_TCP, 1, 18, 80), 2, "SYN-ACK bypasses SYN limiter");
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 2, "Established ACK bypasses exhausted SYN bucket");
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 2, "Established fast path still allowed");
    run(fd, packet(6, IPPROTO_UDP, 0, 0, 5201), 2, "UDP unaffected by SYN limiter");
    size_t syn_len = packet(6, IPPROTO_TCP, 0, 2, 80);
    ((struct tcphdr *)(frame + 54))->source = htons(50000);
    run(fd, syn_len, 1, "Source-port rotation cannot bypass SYN limit");
    struct flow_key rejected = {.src_port = htons(50000), .dst_port = htons(80),
        .proto = IPPROTO_TCP, .family = FW_AF_INET6};
    inet_pton(AF_INET6, "fd10:10:1::20", rejected.src_ip6.words);
    inet_pton(AF_INET6, "fd10:10:2::10", rejected.dst_ip6.words);
    struct flow_entry entry;
    int state_map = bpf_object__find_map_fd_by_name(obj,
        FW_ENGINE == FW_ENGINE_DUALMAP ? "ct_syn_map" : "conntrack_map");
    assert(bpf_map_lookup_elem(state_map, &rejected, &entry) < 0);
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress_prog"));
    rate_test_hook = 1;
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 2, "TC ingress enforces SYN limit");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress_prog"));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 0, "TC egress does not charge SYN budget");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 2, "IPv4 has independent source budget");
    bucket = (struct rate_bucket){.last_refill_ns = ~0ULL};
    assert(!bpf_map_update_elem(rate_total, &key, &bucket, BPF_EXIST | BPF_F_LOCK));
    syn_len = packet(6, IPPROTO_TCP, 0, 2, 80);
    ((struct ipv6hdr *)(frame + 14))->saddr.s6_addr[15]++;
    run(fd, syn_len, 1, "Aggregate exhaustion blocks a fresh source");
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 2, "Aggregate exhaustion leaves established data alone");
    limits.aggregate_enabled = 0;
    assert(!bpf_map_update_elem(rate_cfg, &key, &limits, BPF_EXIST));
    assert(!bpf_map_delete_elem(rate_total, &key));
    syn_len = packet(6, IPPROTO_TCP, 0, 2, 80);
    ((struct ipv6hdr *)(frame + 14))->saddr.s6_addr[15]++;
    run(fd, syn_len, 2, "Per-source limiter works without aggregate bucket");
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 1, "Source exhaustion still enforced with aggregate disabled");
    assert(!bpf_map_delete_elem(rate_cfg, &key));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 80), 2, "Unselected interface bypasses SYN limiter");
#endif
#if FW_ANTI_SPOOF
    int spoof_scopes = bpf_object__find_map_fd_by_name(obj, "anti_spoof_scopes");
    int spoof_prefix = bpf_object__find_map_fd_by_name(obj, "anti_spoof_prefix");
    __u32 scope = 1, allow = 1, deny = 0;
    assert(!bpf_map_update_elem(spoof_scopes, &scope, &allow, BPF_ANY));
    struct anti_spoof_key prefix = {.prefixlen = ANTI_SPOOF_SCOPE_BITS + 64,
        .ifindex = 1, .family = FW_AF_INET6};
    inet_pton(AF_INET6, "fd10:10:1::", prefix.address);
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &allow, BPF_ANY));
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 2, "Anti-spoof allows configured IPv6 prefix");
    prefix.prefixlen = ANTI_SPOOF_SCOPE_BITS + 128;
    inet_pton(AF_INET6, "fd10:10:1::20", prefix.address);
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &deny, BPF_ANY));
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 1, "More-specific source deny overrides cached flow");
    assert(!bpf_map_delete_elem(spoof_prefix, &prefix));
    size_t spoof_len = packet(6, IPPROTO_TCP, 0, 16, 80);
    ((struct ipv6hdr *)(frame + 14))->saddr.s6_addr[5]++;
    run(fd, spoof_len, 1, "IPv6 outside source prefix rejected");
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 1, "Unconfigured IPv4 family fails closed");
    prefix = (struct anti_spoof_key){.prefixlen = ANTI_SPOOF_SCOPE_BITS + 24,
        .ifindex = 1, .family = FW_AF_INET};
    inet_pton(AF_INET, "10.10.1.0", prefix.address);
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &allow, BPF_ANY));
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 2, "IPv4 allowed source prefix");
    spoof_len = packet(4, IPPROTO_TCP, 0, 2, 80);
    ((struct iphdr *)(frame + 14))->saddr = inet_addr("10.11.1.20");
    run(fd, spoof_len, 1, "IPv4 outside source prefix rejected");
    prefix.prefixlen = ANTI_SPOOF_SCOPE_BITS;
    memset(prefix.address, 0, sizeof(prefix.address));
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &allow, BPF_ANY));
    prefix.prefixlen = ANTI_SPOOF_SCOPE_BITS + 24;
    inet_pton(AF_INET, "10.10.1.0", prefix.address);
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &deny, BPF_ANY));
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 1, "WAN-style internal source deny overrides default allow");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress_prog"));
    rate_test_hook = 1;
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 2, "TC ingress anti-spoof drop");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress_prog"));
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 0, "TC egress bypasses source validation");
    /* A scope must not accidentally inherit another interface's prefixes. */
    scope = 2;
    assert(!bpf_map_update_elem(spoof_scopes, &scope, &allow, BPF_ANY));
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress_prog"));
    test_ifindex = 2;
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 80), 2, "Protected interface cannot inherit another scope's prefixes");
    test_ifindex = 1;
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    prefix = (struct anti_spoof_key){.prefixlen = ANTI_SPOOF_SCOPE_BITS + 128,
        .ifindex = 1, .family = FW_AF_INET6};
    inet_pton(AF_INET6, "fd10:10:1::20", prefix.address);
    assert(!bpf_map_update_elem(spoof_prefix, &prefix, &deny, BPF_ANY));
    spoof_len = packet(6, IPPROTO_ICMPV6, 0, 135, 0);
    ((struct ipv6hdr *)(frame + 14))->hop_limit = 255;
    ((struct ipv6hdr *)(frame + 14))->payload_len = htons(24);
    run(fd, spoof_len + 16, 1, "Neighbor Discovery cannot bypass explicit source deny");
    scope = 1;
    assert(!bpf_map_delete_elem(spoof_scopes, &scope));
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 80), 2, "Unselected ingress bypasses anti-spoof policy");
#endif
#if FW_CONN_LIMIT
    int cap_cfg = bpf_object__find_map_fd_by_name(obj, "conn_limit_cfg");
    r = (struct fw_rule){.flags = RULE_FLAG_ACTIVE, .action = ACTION_PASS};
    key = 0;
    assert(!bpf_map_update_elem(map, &key, &r, BPF_ANY));
    int cap_src = bpf_object__find_map_fd_by_name(obj, "conn_limit_src");
    int cap_on = bpf_object__find_map_fd_by_name(obj, "conn_limit_on");
    int cap_hint = bpf_object__find_map_fd_by_name(obj, "conn_limit_hint");
    __u32 cap_scope = 1, cap_max = 2, cap_zero = 0, cap_enabled = 1;
    assert(!bpf_map_update_elem(cap_cfg, &cap_scope, &cap_max, BPF_ANY));
    assert(!bpf_map_update_elem(cap_on, &cap_zero, &cap_enabled, BPF_ANY));
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8080), 2, "Connection cap first SYN");
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8080), 2, "SYN retransmission reuses slot");
    run(fd, packet(6, IPPROTO_TCP, 1, 18, 8080), 2, "Connection cap reverse SYN-ACK");
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 8080), 2, "Connection cap handshake completes");
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8081), 2, "Connection cap second SYN");
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8082), 1, "Connection cap rejects third tuple");
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 8080), 2, "Existing data passes at connection cap");
    run(fd, packet(6, IPPROTO_TCP, 1, 16, 8080), 2, "Reverse data renews same connection");
    run(fd, packet(4, IPPROTO_TCP, 0, 2, 8082), 2, "IPv4 independent connection budget");
    run(fd, packet(6, IPPROTO_UDP, 0, 0, 8082), 2, "UDP not connection limited");
    struct connection_source owner = {.family = FW_AF_INET6};
    inet_pton(AF_INET6, "fd10:10:1::20", owner.address);
    struct connection_source_slots slots;
    assert(!bpf_map_lookup_elem_flags(cap_src, &owner, &slots, BPF_F_LOCK));
    assert(slots.slots[0].timeout_ns == TCP_ESTABLISHED_TIMEOUT_NS);
    assert(slots.slots[1].timeout_ns == TCP_SYN_TIMEOUT_NS);
    /* Evict accelerator entries; full-tuple fallback must still renew activity. */
    struct flow_key hint_key = slots.slots[0].flow;
    assert(!bpf_map_delete_elem(cap_hint, &hint_key));
    run(fd, packet(6, IPPROTO_TCP, 0, 16, 8080), 2, "Hint eviction preserves established accounting");
    run(fd, packet(6, IPPROTO_TCP, 0, 4, 8080), 2, "RST retains closing slot");
    assert(!bpf_map_lookup_elem_flags(cap_src, &owner, &slots, BPF_F_LOCK));
    assert(slots.slots[0].timeout_ns == TCP_CLOSE_TIMEOUT_NS);
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8082), 1, "Closing slot remains counted");
    slots.slots[0].last_seen_ns = slots.slots[0].expires_ns = 1;
    assert(!bpf_map_update_elem(cap_src, &owner, &slots, BPF_EXIST | BPF_F_LOCK));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8082), 2, "Expired closing slot reclaimed");
    assert(!bpf_map_lookup_elem_flags(cap_src, &owner, &slots, BPF_F_LOCK));
    slots.slots[1].last_seen_ns = slots.slots[1].expires_ns = 1;
    assert(!bpf_map_update_elem(cap_src, &owner, &slots, BPF_EXIST | BPF_F_LOCK));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8083), 2, "Expired half-open slot reclaimed");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress_prog"));
    rate_test_hook = 1;
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8084), 2, "TC ingress enforces connection cap");
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress_prog"));
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8084), 0, "TC egress bypasses connection admission");
    assert(!bpf_map_delete_elem(cap_cfg, &cap_scope));
    fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_firewall_prog"));
    rate_test_hook = 0;
    run(fd, packet(6, IPPROTO_TCP, 0, 2, 8085), 2, "Unselected ingress bypasses connection cap");
#endif
    struct bpf_map *perf = bpf_object__find_map_by_name(obj, "perf_map");
    if (perf) {
        int cpus = libbpf_num_possible_cpus();
        struct metric { __u64 total, count, min, max; };
        struct metric *values = calloc(cpus, sizeof(*values));
        assert(values);
        __u64 count = 0;
        for (__u32 i = 0; i < bpf_map__max_entries(perf); i++) {
            assert(!bpf_map_lookup_elem(bpf_map__fd(perf), &i, values));
            for (int cpu = 0; cpu < cpus; cpu++) count += values[cpu].count;
        }
        assert(count > 0);
        free(values);
        puts("Component timing metrics populated for dual-stack packets");
    }
    printf("%d XDP/TC dual-stack dataplane tests passed (%s)\n", tests, path);
    bpf_object__close(obj);
}

int main(int argc, char **argv)
{
    unit_tests();
    if (argc > 1) dataplane_tests(argv[1]);
    return 0;
}
