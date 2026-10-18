#ifndef __CORE_RATE_LIMIT_H__
#define __CORE_RATE_LIMIT_H__

#include <linux/bpf.h>
#include <linux/types.h>

#define RATE_SOURCE_ENTRIES 65536
#define RATE_SCOPE_ENTRIES 16
#define RATE_CREDIT_PER_PACKET 1000000000ULL
#define RATE_MAX_VALUE 1000000000U

/* One profile and aggregate budget per selected ingress interface. */
struct syn_rate_config {
    __u32 source_rate;
    __u32 source_burst;
    __u32 aggregate_rate;
    __u32 aggregate_burst;
    __u32 aggregate_enabled;
};

struct rate_source_key {
    __u32 ifindex;
    __u32 address[4];
    __u8 family;
    __u8 pad[3];
};

struct rate_bucket {
    struct bpf_spin_lock lock;
    __u32 pad;
    __u64 last_refill_ns;
    __u64 credit;
};

/* Caller holds the bucket lock. Credit is in fractional packet units:
 * elapsed nanoseconds * packets/second, so no fractional refill is lost.
 * Validated rates/bursts <= RATE_MAX_VALUE keep all products within u64. */
static __inline __attribute__((always_inline)) int
rate_bucket_take(struct rate_bucket *bucket, __u64 now, __u32 rate, __u32 burst)
{
    if (!rate || !burst || rate > RATE_MAX_VALUE || burst > RATE_MAX_VALUE)
        return 0;
    __u64 capacity = (__u64)burst * RATE_CREDIT_PER_PACKET;
    __u64 credit = bucket->credit;
    if (credit > capacity)
        credit = capacity;
    if (now > bucket->last_refill_ns) {
        __u64 elapsed = now - bucket->last_refill_ns;
        /* Beyond this interval the bucket is certainly full; avoid overflow. */
        __u64 full_interval = capacity / rate + (capacity % rate != 0);
        if (elapsed >= full_interval)
            credit = capacity;
        else {
            __u64 added = elapsed * rate;
            credit = added >= capacity - credit ? capacity : credit + added;
        }
        bucket->last_refill_ns = now;
    }
    int allow = credit >= RATE_CREDIT_PER_PACKET;
    bucket->credit = allow ? credit - RATE_CREDIT_PER_PACKET : credit;
    return allow;
}

#endif
