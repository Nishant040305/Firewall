#ifndef __PROTOCOLS_PROTOCOL_ADAPTER_H__
#define __PROTOCOLS_PROTOCOL_ADAPTER_H__

#include <linux/types.h>
#include <stddef.h>
#include <core/types.h>

/* Protocol Adapter Interface */
struct protocol_adapter {
    const char *name;
    __u8 proto_num;

    /* Format 5-tuple packet telemetry event into human-readable buffer */
    void (*format_event)(const struct packet_event *evt, char *buf, size_t len);
};

#endif /* __PROTOCOLS_PROTOCOL_ADAPTER_H__ */
