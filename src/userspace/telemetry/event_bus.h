#ifndef __TELEMETRY_EVENT_BUS_H__
#define __TELEMETRY_EVENT_BUS_H__

struct ring_buffer;
#include <linux/types.h>
#include <core/types.h>
#include <core/stats.h>

/* Minimalist Event Bus & Console Print Telemetry */
struct event_bus {
    struct ring_buffer *rb;
    int stats_map_fd;
};

/* Initialize Event Bus with RingBuffer and Stats Map FDs */
int event_bus_init(struct event_bus *bus, int ringbuf_fd, int stats_map_fd);

/* Poll RingBuffer for incoming events and print them to console */
int event_bus_poll(struct event_bus *bus, int timeout_ms);

/* Collect per-CPU stats snapshot and print to console */
void event_bus_collect_stats(struct event_bus *bus);

/* Clean up Event Bus and RingBuffer */
void event_bus_cleanup(struct event_bus *bus);

#endif /* __TELEMETRY_EVENT_BUS_H__ */
