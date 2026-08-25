#ifndef __PROTOCOLS_PROTOCOL_REGISTRY_H__
#define __PROTOCOLS_PROTOCOL_REGISTRY_H__

#include <linux/types.h>
#include "protocol_adapter.h"

/* Initialize builtin protocol adapters */
void protocol_registry_init(void);

/* Fast O(1) protocol adapter lookup by IP protocol number */
const struct protocol_adapter *protocol_registry_get(__u8 proto);

/* Register custom protocol adapter */
int protocol_registry_add(const struct protocol_adapter *adapter);

#endif /* __PROTOCOLS_PROTOCOL_REGISTRY_H__ */
