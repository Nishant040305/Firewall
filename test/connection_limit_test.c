#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <core/types.h>
#include <core/connection_limit.h>
#include <bpf/bpf_helpers.h>
#include "core/config.h"
#include "core/context.bpf.h"

#define __CORE_MAPS_BPF_H__
#define __CORE_HELPERS_BPF_H__
static int conn_limit_cfg, conn_limit_src, conn_limit_hint, conn_limit_zero, conn_limit_on, conn_limit_tmp;
static struct connection_scratch scratch;
static __u32 maximum = 2, enabled = 1;
static struct connection_source owner;
static struct connection_source_slots slots;
static struct connection_zero_template empty;
static int present, full;
static __u64 counters[STAT_MAX_COUNTERS];
static pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t source_lock = PTHREAD_MUTEX_INITIALIZER;
static void *lookup(const void *map, const void *key)
{
    if (map == &conn_limit_cfg) return *(__u32 *)key == 7 ? &maximum : NULL;
    if (map == &conn_limit_on) return &enabled;
    if (map == &conn_limit_tmp) return &scratch;
    if (map == &conn_limit_zero) return &empty;
    if (map == &conn_limit_hint) return NULL; /* Always exercise eviction fallback. */
    pthread_mutex_lock(&map_lock);
    void *value = present && !memcmp(key, &owner, sizeof(owner)) ? &slots : NULL;
    pthread_mutex_unlock(&map_lock);
    return value;
}
static long update(const void *map, const void *key, const void *value, __u64 flags)
{
    if (map == &conn_limit_hint) return 0;
    assert(map == &conn_limit_src && flags == BPF_NOEXIST);
    pthread_mutex_lock(&map_lock);
    int result = -1;
    if (!present && !full) {
        memcpy(&owner, key, sizeof(owner));
        memcpy(&slots, value, sizeof(slots));
        present = 1;
        result = 0;
    }
    pthread_mutex_unlock(&map_lock);
    return result;
}
static void lock(struct bpf_spin_lock *unused) { (void)unused; pthread_mutex_lock(&source_lock); }
static void unlock(struct bpf_spin_lock *unused) { (void)unused; pthread_mutex_unlock(&source_lock); }
static void make_reverse_flow_key(struct pkt_ctx *pkt, struct flow_key *key)
{
    *key = pkt->flow;
    key->src_ip = pkt->flow.dst_ip;
    key->dst_ip = pkt->flow.src_ip;
    key->src_ip6 = pkt->flow.dst_ip6;
    key->dst_ip6 = pkt->flow.src_ip6;
    key->src_port = pkt->flow.dst_port;
    key->dst_port = pkt->flow.src_port;
}
#define bpf_map_lookup_elem lookup
#define bpf_map_update_elem update
#define bpf_spin_lock lock
#define bpf_spin_unlock unlock
#define inc_stat(key) __sync_fetch_and_add(&counters[key], 1)
#include "core/connection_limit.bpf.h"

static struct pkt_ctx packet(__u16 port)
{
    return (struct pkt_ctx){.direction = DIR_INGRESS, .ifindex = 7,
        .tcp_flags = 2, .flow = {.src_ip = 42, .dst_ip = 99, .src_port = port,
            .dst_port = 80, .proto = PROTO_TCP, .family = FW_AF_INET}};
}
static void reset(void)
{
    present = full = 0;
    maximum = 2;
    memset(&slots, 0, sizeof(slots));
    memset(counters, 0, sizeof(counters));
}
static void *worker(void *arg)
{
    struct pkt_ctx pkt = packet((unsigned long)arg);
    return (void *)(unsigned long)connection_limit_admit(&pkt, 1000000000);
}
int main(void)
{
    reset();
    struct pkt_ctx pkt = packet(1);
    assert(connection_limit_admit(&pkt, 1000000000));
    assert(connection_limit_admit(&pkt, 1000000001));
    pkt = packet(2);
    assert(connection_limit_admit(&pkt, 1000000000));
    pkt = packet(3);
    assert(!connection_limit_admit(&pkt, 1000000000));
    assert(connection_limit_admit(&pkt, 1000000002 + TCP_SYN_TIMEOUT_NS));
    pkt.tcp_flags = 16;
    pkt.conn_state = CONN_STATE_ESTABLISHED;
    connection_limit_touch(&pkt, 1000000003 + TCP_SYN_TIMEOUT_NS);
    assert(slots.slots[0].timeout_ns == TCP_ESTABLISHED_TIMEOUT_NS);
    struct pkt_ctx reverse = pkt;
    make_reverse_flow_key(&pkt, &reverse.flow);
    reverse.tcp_flags = 4;
    connection_limit_touch(&reverse, 1000000004 + TCP_SYN_TIMEOUT_NS);
    assert(slots.slots[0].timeout_ns == TCP_CLOSE_TIMEOUT_NS);
    reset();
    full = 1;
    pkt = packet(1);
    assert(!connection_limit_admit(&pkt, 1));
    assert(counters[STAT_CONN_LIMIT_MAP_FULL] == 1);
    pkt.direction = DIR_EGRESS;
    assert(connection_limit_admit(&pkt, 1));
    reset();
    maximum = CONN_LIMIT_SLOTS;
    pthread_t threads[64];
    for (unsigned long i = 0; i < 64; i++)
        assert(!pthread_create(&threads[i], NULL, worker, (void *)(i + 1)));
    unsigned admitted = 0;
    for (int i = 0; i < 64; i++) {
        void *result;
        assert(!pthread_join(threads[i], &result));
        admitted += (unsigned long)result;
    }
    assert(admitted == CONN_LIMIT_SLOTS);
    struct firewall_config cfg;
    config_set_defaults(&cfg);
    assert(!cfg.connection_limit.enabled && cfg.connection_limit.source_max == 32);
    char path[] = "/tmp/opencode/connection-config-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "w");
    assert(file);
    fputs("connection_limit:\n  enabled: true\n  interfaces:\n  source_max: 3\n", file);
    fclose(file);
    assert(!config_load_file(path, &cfg));
    assert(cfg.connection_limit.enabled && cfg.connection_limit.source_max == 3);
    assert(!config_validate(&cfg));
    cfg.connection_limit.source_max = 33;
    assert(config_validate(&cfg) < 0);
    file = fopen(path, "w");
    assert(file);
    fputs("connection_limit:\n  source_max: -1\n", file);
    fclose(file);
    assert(config_load_file(path, &cfg) < 0);
    unlink(path);
    puts("Connection limit admission, expiry, reverse activity, map-full, concurrency and config tests passed");
    return 0;
}
