#include <stdio.h>
#include <string.h>
#include <core/constants.h>
#include "protocol_registry.h"

extern const struct protocol_adapter tcp_adapter;
extern const struct protocol_adapter udp_adapter;
extern const struct protocol_adapter icmp_adapter;

static const struct protocol_adapter *registry[256] = {0};
static int initialized = 0;

void protocol_registry_init(void)
{
    if (initialized) return;

    memset(registry, 0, sizeof(registry));
    registry[PROTO_TCP]  = &tcp_adapter;
    registry[PROTO_UDP]  = &udp_adapter;
    registry[PROTO_ICMP] = &icmp_adapter;

    initialized = 1;
}

const struct protocol_adapter *protocol_registry_get(__u8 proto)
{
    if (!initialized) {
        protocol_registry_init();
    }
    return registry[proto];
}

int protocol_registry_add(const struct protocol_adapter *adapter)
{
    if (!adapter) return -1;
    if (!initialized) {
        protocol_registry_init();
    }
    registry[adapter->proto_num] = adapter;
    return 0;
}
