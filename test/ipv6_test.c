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
static void run(int fd, size_t len, unsigned expected, const char *name)
{
    unsigned char out[512];
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = frame, .data_size_in = len,
        .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
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
