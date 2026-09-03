#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include "firewall_ctx.h"
#include "rules_mgr.h"
#include "conntrack_mgr.h"
#include "stats_mgr.h"
#include "../protocols/protocol_registry.h"

int firewall_ctx_init(struct firewall_ctx *ctx, int argc, char **argv)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->running = 1;

    /* 1. Parse CLI Arguments */
    if (parse_cli_args(argc, argv, &ctx->opts) < 0) {
        return -1;
    }

    /* 2. Handle Subcommand Invocations (firewallctl rule / conntrack / stats) */
    if (ctx->opts.cmd != CMD_RUN) {
        if (bpf_loader_open_pinned_maps(&ctx->loader) < 0) {
            fprintf(stderr, "[-] Error: Firewall maps not found at '%s'.\n", BPF_FS_PATH);
            fprintf(stderr, "    Make sure the firewall daemon is running (e.g., sudo ./build/fw-ctl -i <iface>).\n");
            return -1;
        }

        switch (ctx->opts.cmd) {
        case CMD_RULE_LIST:
            return rules_mgr_list(ctx->loader.rules_map_fd);
        case CMD_RULE_ADD: {
            __u32 idx = 0;
            if (rules_mgr_add(ctx->loader.rules_map_fd, &ctx->opts.new_rule, &idx) == 0) {
                printf("[+] Successfully added firewall rule ID #%u\n", idx + 1);
                return 0;
            }
            return -1;
        }
        case CMD_RULE_DEL:
            if (ctx->opts.del_rule_id == 0) {
                fprintf(stderr, "[-] Usage: fw-ctl rule del <rule_id>\n");
                return -1;
            }
            if (rules_mgr_del(ctx->loader.rules_map_fd, ctx->opts.del_rule_id - 1) == 0) {
                printf("[+] Deleted rule ID #%u\n", ctx->opts.del_rule_id);
                return 0;
            }
            return -1;
        case CMD_RULE_FLUSH:
            return rules_mgr_flush(ctx->loader.rules_map_fd);
        case CMD_RULE_LOAD:
            return rules_mgr_load_file(ctx->loader.rules_map_fd, ctx->opts.rules_path);
        case CMD_CONNTRACK_LIST:
            return conntrack_mgr_list(ctx->loader.conntrack_map_fd);
        case CMD_CONNTRACK_FLUSH:
            return conntrack_mgr_flush(ctx->loader.conntrack_map_fd);
        case CMD_STATS_SHOW:
            return stats_mgr_show(ctx->loader.stats_map_fd, ctx->opts.json_output);
        case CMD_STATS_RESET:
            return stats_mgr_reset(ctx->loader.stats_map_fd);
        default:
            return 0;
        }
    }

    /* 3. Initialize Protocol Registry for Daemon / Monitor Mode */
    protocol_registry_init();

    /* 4. Load & Validate Configuration */
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

    /* 5. Load BPF Object & Attach Hook (XDP / TC) */
    const char *bpf_obj = "build/firewall.bpf.o";
    if (bpf_loader_init(&ctx->loader, bpf_obj, &ctx->config) < 0) {
        return -1;
    }

    /* 6. Load Initial Rules from config/rules.yaml if present (Step 8) */
    const char *rules_file = ctx->opts.rules_path ? ctx->opts.rules_path : "config/rules.yaml";
    if (access(rules_file, F_OK) == 0 && ctx->loader.rules_map_fd >= 0) {
        rules_mgr_load_file(ctx->loader.rules_map_fd, rules_file);
    }

    /* 7. Initialize Event Bus for Real-time 5-tuple Telemetry */
    if (event_bus_init(&ctx->bus, ctx->loader.events_ringbuf_fd, ctx->loader.stats_map_fd) < 0) {
        fprintf(stderr, "[-] Warning: Failed to initialize EventBus\n");
    }

    return 0;
}

int firewall_ctx_run(struct firewall_ctx *ctx)
{
    /* If this was a one-shot subcommand, exit immediately */
    if (ctx->opts.cmd != CMD_RUN) {
        return 0;
    }

    printf("\n[*] Running Stateful Firewall on '%s' (%s, %s)\n",
           ctx->config.interface,
           direction_to_str(ctx->config.direction),
           mode_to_str(ctx->loader.mode));
    printf("[*] Real-time 5-tuple telemetry streaming active. Press Ctrl+C to stop.\n\n");

    time_t last_stats = time(NULL);
    while (ctx->running) {
        /* Poll and print 5-tuple events from RingBuffer */
        event_bus_poll(&ctx->bus, ctx->config.global.ringbuf_poll_timeout_ms);

        /* Periodic stats printing */
        time_t now = time(NULL);
        if (now - last_stats >= ctx->config.global.stats_interval_sec) {
            stats_mgr_show(ctx->loader.stats_map_fd, 0);
            last_stats = now;
        }
    }

    return 0;
}

void firewall_ctx_reload(struct firewall_ctx *ctx)
{
    printf("\n[*] SIGHUP received: Reloading configuration and rules...\n");
    const char *cfg_file = ctx->opts.config_path ? ctx->opts.config_path : "config/firewall.yaml";
    if (access(cfg_file, F_OK) == 0) {
        config_load_file(cfg_file, &ctx->config);
    }
    const char *rules_file = ctx->opts.rules_path ? ctx->opts.rules_path : "config/rules.yaml";
    if (access(rules_file, F_OK) == 0 && ctx->loader.rules_map_fd >= 0) {
        rules_mgr_flush(ctx->loader.rules_map_fd);
        rules_mgr_load_file(ctx->loader.rules_map_fd, rules_file);
    }
    printf("[+] Configuration reload complete.\n");
}

void firewall_ctx_stop(struct firewall_ctx *ctx)
{
    if (ctx->opts.cmd != CMD_RUN) return;

    printf("\n\n[*] Shutting down firewall...\n");
    event_bus_cleanup(&ctx->bus);
    bpf_loader_cleanup(&ctx->loader);
    printf("[+] Detached and unloaded successfully.\n");
}
