#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <core/types.h>
#include <core/rate_limit.h>
#include <bpf/bpf_helpers.h>
#include "core/config.h"
#include "core/context.bpf.h"

/* Exercise the real kernel limiter with bounded mock maps, including
 * first-insertion races. Locks serialize bucket values just as in BPF. */
#define __CORE_MAPS_BPF_H__
#define __CORE_HELPERS_BPF_H__
static int syn_rate_config, syn_rate_total, syn_rate_sources;
static struct syn_rate_config config;
static struct rate_bucket aggregate, sources[4];
static struct rate_source_key keys[4];
static int used, map_full;
static unsigned total_lookups;
static __u64 counters[STAT_MAX_COUNTERS];
static pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t bucket_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *lookup(const void *map, const void *key)
{
    if (map == &syn_rate_config) return *(__u32 *)key == 7 ? &config : NULL;
    if (map == &syn_rate_total) {
        __sync_fetch_and_add(&total_lookups, 1);
        return &aggregate;
    }
    void *found = NULL;
    pthread_mutex_lock(&map_mutex);
    for (int i = 0; i < used; i++)
        if (!memcmp(&keys[i], key, sizeof(keys[i]))) found = &sources[i];
    pthread_mutex_unlock(&map_mutex);
    return found;
}

static long update(const void *map, const void *key, const void *value, __u64 flags)
{
    assert(map == &syn_rate_sources && flags == BPF_NOEXIST);
    pthread_mutex_lock(&map_mutex);
    int result = -1;
    for (int i = 0; i < used; i++)
        if (!memcmp(&keys[i], key, sizeof(keys[i]))) goto done;
    if (!map_full && used < 4) {
        memcpy(&keys[used], key, sizeof(keys[used]));
        memcpy(&sources[used++], value, sizeof(sources[0]));
        result = 0;
    }
done:
    pthread_mutex_unlock(&map_mutex);
    return result;
}
static void lock_bucket(struct bpf_spin_lock *lock) { (void)lock; pthread_mutex_lock(&bucket_mutex); }
static void unlock_bucket(struct bpf_spin_lock *lock) { (void)lock; pthread_mutex_unlock(&bucket_mutex); }
#define bpf_map_lookup_elem lookup
#define bpf_map_update_elem update
#define bpf_spin_lock lock_bucket
#define bpf_spin_unlock unlock_bucket
#define inc_stat(key) __sync_fetch_and_add(&counters[key], 1)
#include "core/rate_limit.bpf.h"

static void reset(__u32 burst)
{
    memset(sources, 0, sizeof(sources));
    memset(counters, 0, sizeof(counters));
    used = map_full = 0;
    total_lookups = 0;
    config = (struct syn_rate_config){100, burst, 10000, 20000, 1};
    aggregate = (struct rate_bucket){.credit = 20000 * RATE_CREDIT_PER_PACKET};
}

static struct pkt_ctx packet(void)
{
    return (struct pkt_ctx){.direction = DIR_INGRESS, .ifindex = 7,
        .family = FW_AF_INET, .src_ip = 42};
}

static void *worker(void *unused)
{
    (void)unused;
    unsigned allowed = 0;
    struct pkt_ctx pkt = packet();
    for (int i = 0; i < 100; i++) allowed += syn_rate_allow(&pkt, 1000000000);
    return (void *)(unsigned long)allowed;
}

static void algorithm_tests(void)
{
    struct rate_bucket b = {.last_refill_ns = 100, .credit = 2 * RATE_CREDIT_PER_PACKET};
    assert(rate_bucket_take(&b, 100, 3, 2));
    assert(rate_bucket_take(&b, 100, 3, 2));
    assert(!rate_bucket_take(&b, 100, 3, 2));
    assert(!rate_bucket_take(&b, 100 + 100000000, 3, 2));
    assert(!rate_bucket_take(&b, 100 + 200000000, 3, 2));
    assert(!rate_bucket_take(&b, 100 + 300000000, 3, 2));
    assert(rate_bucket_take(&b, 100 + 400000000, 3, 2));
    __u64 last = b.last_refill_ns;
    assert(!rate_bucket_take(&b, 0, 3, 2));
    assert(b.last_refill_ns == last);
    assert(rate_bucket_take(&b, ~0ULL, RATE_MAX_VALUE, RATE_MAX_VALUE));
    assert(b.credit == (__u64)RATE_MAX_VALUE * RATE_CREDIT_PER_PACKET - RATE_CREDIT_PER_PACKET);
    assert(!rate_bucket_take(&b, 0, 0, 1));
    b = (struct rate_bucket){0};
    /* This multiplication overflowed without the full-refill bound. */
    assert(rate_bucket_take(&b, 100000000000ULL, RATE_MAX_VALUE, RATE_MAX_VALUE));
}

static void limiter_tests(void)
{
    reset(2);
    struct pkt_ctx pkt = packet();
    assert(syn_rate_allow(&pkt, 1000000000));
    pkt.src_port = 1234; /* Port rotation must not reset the source budget. */
    assert(syn_rate_allow(&pkt, 1000000000));
    assert(!syn_rate_allow(&pkt, 1000000000));
    assert(pkt.reason == REASON_RATE_LIMIT && counters[STAT_RATE_SOURCE_DROP] == 1);
    assert(syn_rate_allow(&pkt, 1010000000));
    pkt.src_ip++;
    assert(syn_rate_allow(&pkt, 1010000000));
    pkt.family = FW_AF_INET6;
    pkt.src_ip6.words[3] = 42;
    assert(syn_rate_allow(&pkt, 1010000000));
    pkt.src_ip6.words[3]++;
    map_full = 1;
    assert(!syn_rate_allow(&pkt, 1010000000));
    assert(counters[STAT_RATE_MAP_FULL] == 1);
    pkt.direction = DIR_EGRESS;
    assert(syn_rate_allow(&pkt, 1010000000));
    pkt.direction = DIR_INGRESS;
    pkt.ifindex = 8;
    assert(syn_rate_allow(&pkt, 1010000000));
    reset(2);
    pkt = packet();
    aggregate = (struct rate_bucket){.last_refill_ns = 1000000000};
    assert(!syn_rate_allow(&pkt, 1000000000));
    assert(counters[STAT_RATE_AGGREGATE_DROP] == 1 && used == 0);

    reset(2);
    config.aggregate_enabled = 0;
    aggregate = (struct rate_bucket){0};
    pkt = packet();
    assert(syn_rate_allow(&pkt, 1000000000));
    assert(syn_rate_allow(&pkt, 1000000000));
    assert(!syn_rate_allow(&pkt, 1000000000));
    pkt.src_ip++;
    assert(syn_rate_allow(&pkt, 1000000000));
    assert(total_lookups == 0 && counters[STAT_RATE_AGGREGATE_DROP] == 0);
    assert(counters[STAT_RATE_SOURCE_DROP] == 1);

    reset(200);
    pthread_t threads[8];
    for (int i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, worker, NULL));
    unsigned allowed = 0;
    for (int i = 0; i < 8; i++) {
        void *result;
        assert(!pthread_join(threads[i], &result));
        allowed += (unsigned long)result;
    }
    assert(allowed == 200 && used == 1 && counters[STAT_RATE_SOURCE_DROP] == 600);
}

static void config_tests(void)
{
    struct firewall_config cfg;
    config_set_defaults(&cfg);
    assert(!cfg.rate_limit.enabled && !config_validate(&cfg));
    assert(!config_load_file("config/firewall.yaml", &cfg));
    assert(cfg.rate_limit.enabled && !config_validate(&cfg));
    assert(!cfg.rate_limit.limits.aggregate_enabled);
    strcpy(cfg.interface, "eth0,eth1");
    assert(config_validate(&cfg) < 0);
    strcpy(cfg.rate_limit.interfaces, "eth0");
#if FW_CONN_LIMIT
    strcpy(cfg.connection_limit.interfaces, "eth0");
#endif
    assert(!config_validate(&cfg));
    cfg.direction = TRAFFIC_DIR_EGRESS;
    assert(config_validate(&cfg) < 0);
    char path[] = "/tmp/opencode/rate-config-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    assert(f);
    fputs("rate_limit:\n  source_rate: -1\n", f);
    fclose(f);
    assert(config_load_file(path, &cfg) < 0);
    f = fopen(path, "w");
    assert(f);
    fputs("rate_limit:\n  enabled: true\n  interfaces:\n  aggregate_enabled: false\n  source_rate: 321\n  source_burst: 654\n", f);
    fclose(f);
    assert(!config_load_file(path, &cfg));
    assert(!cfg.rate_limit.interfaces[0]);
    assert(cfg.rate_limit.limits.source_rate == 321 && cfg.rate_limit.limits.source_burst == 654);
    assert(!cfg.rate_limit.limits.aggregate_enabled);
    cfg.direction = TRAFFIC_DIR_BOTH;
    strcpy(cfg.interface, "eth0");
    cfg.rate_limit.limits.aggregate_rate = cfg.rate_limit.limits.aggregate_burst = 0;
    assert(!config_validate(&cfg));
    cfg.rate_limit.limits.aggregate_enabled = 1;
    assert(config_validate(&cfg) < 0);
    unlink(path);
}

int main(void)
{
    algorithm_tests();
    limiter_tests();
    config_tests();
    puts("SYN limiter arithmetic, concurrency, scopes, exhaustion and config tests passed");
}
