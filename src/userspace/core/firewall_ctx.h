#ifndef __CORE_FIREWALL_CTX_H__
#define __CORE_FIREWALL_CTX_H__

#include "bpf_loader.h"
#include "config.h"
#include "cli.h"
#include "../telemetry/event_bus.h"
#include <signal.h>

/* Facade pattern: Aggregates all subsystems into a single lifecycle manager */
struct firewall_ctx {
    struct firewall_options opts;
    struct firewall_config config;
    struct bpf_loader_ctx loader;
    struct event_bus bus;
    volatile sig_atomic_t running;
};

/* Initialize all firewall subsystems */
int firewall_ctx_init(struct firewall_ctx *ctx, int argc, char **argv);

/* Start the main polling & telemetry loop */
int firewall_ctx_run(struct firewall_ctx *ctx);

/* Hot-reload configuration without restart */
void firewall_ctx_reload(struct firewall_ctx *ctx);

/* Gracefully shut down and detach from kernel */
void firewall_ctx_stop(struct firewall_ctx *ctx);

#endif /* __CORE_FIREWALL_CTX_H__ */
