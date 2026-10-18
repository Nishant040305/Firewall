#ifndef __CORE_CONNECTION_LIMIT_H__
#define __CORE_CONNECTION_LIMIT_H__
#include <linux/bpf.h>
#include <core/conntrack.h>

#define CONN_LIMIT_SLOTS 32
#define CONN_LIMIT_SOURCES 4096
#define CONN_LIMIT_HINTS 65536

struct connection_source {
    __u32 address[4];
    __u32 family;
};
struct connection_slot {
    struct flow_key flow; /* Initiator -> responder; reverse isn't a second connection. */
    __u64 last_seen_ns;
    __u64 expires_ns;
    __u64 timeout_ns; /* Zero means unused. */
};
struct connection_source_slots {
    struct bpf_spin_lock lock;
    __u32 pad;
    struct connection_slot slots[CONN_LIMIT_SLOTS];
};
struct connection_hint {
    struct connection_source source;
    __u32 slot;
};
struct connection_zero_template {
    __u64 words[sizeof(struct connection_source_slots) / sizeof(__u64)];
};
struct connection_scratch {
    struct flow_key reverse;
    struct connection_hint hint;
};
#endif
