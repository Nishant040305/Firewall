#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include "firewall_ctx.h"
#include "../protocols/protocol_registry.h"

int firewall_ctx_init(struct firewall_ctx *ctx, int argc, char **argv)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->running = 1;

    /* 1. Parse CLI Arguments */
    if (parse_cli_args(argc, argv, &ctx->opts) < 0) {
        return -1;
    }

    /* 2. Initialize Protocol Registry */
    protocol_registry_init();

    /* 3. Load & Validate Configuration */
    config_set_defaults(&ctx->config);
    const char *cfg_file = ctx->opts.config_path ? ctx->opts.config_path : "config/firewall.yaml";
    if (access(cfg_file, F_OK) == 0) {
        config_load_file(cfg_file, &ctx->config);
    }

    /* Apply CLI overrides */
    if (ctx->opts.iface) {
        snprintf(ctx->config.interface, sizeof(ctx->config.interface), "%s", ctx->opts.iface);
    }
    if (ctx->opts.direction) {
        if (strcasecmp(ctx->opts.direction, "in") == 0 || strcasecmp(ctx->opts.direction, "ingress") == 0) {
            ctx->config.direction = TRAFFIC_DIR_INGRESS;
        } else if (strcasecmp(ctx->opts.direction, "out") == 0 || strcasecmp(ctx->opts.direction, "egress") == 0) {
            ctx->config.direction = TRAFFIC_DIR_EGRESS;
        } else if (strcasecmp(ctx->opts.direction, "both") == 0 || strcasecmp(ctx->opts.direction, "all") == 0) {
            ctx->config.direction = TRAFFIC_DIR_BOTH;
        }
    }
    if (ctx->opts.mode) {
        if (strcasecmp(ctx->opts.mode, "hybrid") == 0 || strcasecmp(ctx->opts.mode, "xdp+tc") == 0 || strcasecmp(ctx->opts.mode, "xdp_tc") == 0) {
            ctx->config.mode = ATTACH_MODE_HYBRID;
        } else if (strcasecmp(ctx->opts.mode, "xdp") == 0) {
            ctx->config.mode = ATTACH_MODE_XDP;
        } else if (strcasecmp(ctx->opts.mode, "tc") == 0) {
            ctx->config.mode = ATTACH_MODE_TC;
        }
    }

    if (config_validate(&ctx->config) < 0) {
        fprintf(stderr, "[-] Invalid configuration\n");
        return -1;
    }
    
    config_dump(&ctx->config);

    /* 4. Load BPF Object & Attach Hook (TC or XDP) */
    const char *bpf_obj = "build/firewall.bpf.o";
    if (bpf_loader_init(&ctx->loader, bpf_obj, &ctx->config) < 0) {
        return -1;
    }

    /* 5. Initialize Event Bus for Real-time 5-tuple Telemetry */
    if (event_bus_init(&ctx->bus, ctx->loader.events_ringbuf_fd, ctx->loader.stats_map_fd) < 0) {
        fprintf(stderr, "[-] Warning: Failed to initialize EventBus\n");
    }

    return 0;
}

int firewall_ctx_run(struct firewall_ctx *ctx)
{
    printf("\n[*] Monitoring %s traffic on '%s' via %s (Press Ctrl+C to stop)...\n\n",
           direction_to_str(ctx->config.direction),
           ctx->config.interface,
           mode_to_str(ctx->loader.mode));

    time_t last_stats = time(NULL);
    while (ctx->running) {
        /* Poll and print 5-tuple events from RingBuffer */
        event_bus_poll(&ctx->bus, ctx->config.global.ringbuf_poll_timeout_ms);

        /* Periodic stats printing */
        time_t now = time(NULL);
        if (now - last_stats >= ctx->config.global.stats_interval_sec) {
            event_bus_collect_stats(&ctx->bus);
            last_stats = now;
        }
    }

    return 0;
}

void firewall_ctx_reload(struct firewall_ctx *ctx)
{
    printf("\n[*] SIGHUP received: Reloading configuration...\n");
    const char *cfg_file = ctx->opts.config_path ? ctx->opts.config_path : "config/firewall.yaml";
    if (access(cfg_file, F_OK) == 0) {
        config_load_file(cfg_file, &ctx->config);
    }
    printf("[+] Configuration reload complete.\n");
}

void firewall_ctx_stop(struct firewall_ctx *ctx)
{
    printf("\n\n[*] Shutting down packet inspector...\n");
    event_bus_cleanup(&ctx->bus);
    bpf_loader_cleanup(&ctx->loader);
    printf("[+] Detached and unloaded successfully.\n");
}
