#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "firewall_ctx.h"
#include "rules_mgr.h"
#include "conntrack_mgr.h"
#include "stats_mgr.h"
#if FW_TIMING
#include "perf_mgr.h"
#endif

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
#if FW_ENGINE == FW_ENGINE_DUALMAP
            puts("Established flows:");
            if (conntrack_mgr_list(ctx->loader.conntrack_map_fd)) return -1;
            puts("Half-open flows:");
            return conntrack_mgr_list(ctx->loader.syn_map_fd);
#else
            return conntrack_mgr_list(ctx->loader.conntrack_map_fd);
#endif
        case CMD_CONNTRACK_FLUSH:
#if FW_ENGINE == FW_ENGINE_DUALMAP
            if (conntrack_mgr_flush(ctx->loader.syn_map_fd, -1)) return -1;
#endif
            return conntrack_mgr_flush(ctx->loader.conntrack_map_fd, ctx->loader.flow_cache_map_fd);
        case CMD_STATS_SHOW:
            return stats_mgr_show(ctx->loader.stats_map_fd, ctx->opts.json_output);
        case CMD_STATS_RESET:
            return stats_mgr_reset(ctx->loader.stats_map_fd);
#if FW_TIMING
        case CMD_PERF_SHOW:
            return perf_mgr_show(ctx->loader.perf_map_fd, ctx->opts.json_output);
        case CMD_PERF_RESET:
            return perf_mgr_reset(ctx->loader.perf_map_fd);
#endif
        default:
            return 0;
        }
    }

    /* 3. Initialize Protocol Registry for Daemon / Monitor Mode */

    /* 4. Load & Validate Configuration */
    config_set_defaults(&ctx->config);
    const char *cfg_file = ctx->opts.config_path ? ctx->opts.config_path : "config/firewall.yaml";
    if (access(cfg_file, F_OK) == 0) {
        if (config_load_file(cfg_file, &ctx->config) < 0) return -1;
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
        } else {
            fprintf(stderr, "[-] Invalid traffic direction: %s\n", ctx->opts.direction);
            return -1;
        }
    }
    if (ctx->opts.mode) {
        if (strcasecmp(ctx->opts.mode, "hybrid") == 0 || strcasecmp(ctx->opts.mode, "xdp+tc") == 0 || strcasecmp(ctx->opts.mode, "xdp_tc") == 0) {
            ctx->config.mode = ATTACH_MODE_HYBRID;
        } else if (strcasecmp(ctx->opts.mode, "xdp") == 0) {
            ctx->config.mode = ATTACH_MODE_XDP;
        } else if (strcasecmp(ctx->opts.mode, "tc") == 0) {
            ctx->config.mode = ATTACH_MODE_TC;
        } else {
            fprintf(stderr, "[-] Invalid attach mode: %s\n", ctx->opts.mode);
            return -1;
        }
    }

    if (config_validate(&ctx->config) < 0) {
        fprintf(stderr, "[-] Invalid configuration\n");
        return -1;
    }
    
    config_dump(&ctx->config);

    /* 5. Load BPF object without attaching hooks. */
    const char *bpf_obj = getenv("BPF_OBJ") ? getenv("BPF_OBJ") : FW_DEFAULT_BPF_OBJ;
    printf("[*] Loading eBPF object: %s\n", bpf_obj);
    if (bpf_loader_init(&ctx->loader, bpf_obj, &ctx->config) < 0) {
        return -1;
    }

    /* 6. Require and verify a nonempty policy before exposing any hook. */
    const char *rules_file = ctx->opts.rules_path ? ctx->opts.rules_path : "config/rules.yaml";
    if (rules_mgr_replace_file(ctx->loader.rules_map_fd, rules_file) < 0) {
        fprintf(stderr, "[-] Policy initialization failed; no firewall hooks attached\n");
        bpf_loader_cleanup(&ctx->loader);
        return -1;
    }

    /* 7. Initialize Event Bus for Real-time 5-tuple Telemetry */
#ifndef MINIMAL_OBSERVABILITY
    if (event_bus_init(&ctx->bus, ctx->loader.events_ringbuf_fd, ctx->loader.stats_map_fd, &ctx->config) < 0) {
        fprintf(stderr, "[-] Visibility initialization failed; detaching firewall\n");
        bpf_loader_cleanup(&ctx->loader);
        return -1;
    }
#endif

    if (bpf_loader_attach(&ctx->loader) < 0) {
#ifndef MINIMAL_OBSERVABILITY
        event_bus_cleanup(&ctx->bus);
#endif
        bpf_loader_cleanup(&ctx->loader);
        return -1;
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
#if FW_LOGGING
    printf("[*] Network evidence: %s (aggregated, not attack alerts). Press Ctrl+C to stop.\n\n",
            ctx->config.telemetry.path);
#else
    puts("[*] Press Ctrl+C to stop.");
#endif

    struct timespec tick;
    clock_gettime(CLOCK_MONOTONIC, &tick);
    time_t last_flush = tick.tv_sec;
#if FW_ENGINE == FW_ENGINE_DUALMAP
    time_t last_gc = tick.tv_sec;
#endif
    while (ctx->running) {
        if (ctx->reload_requested) {
            ctx->reload_requested = 0;
            firewall_ctx_reload(ctx);
        }
        /* Poll and aggregate metadata events from RingBuffer. */
#ifndef MINIMAL_OBSERVABILITY
        int rc = event_bus_poll(&ctx->bus, ctx->config.global.ringbuf_poll_timeout_ms);
        if (rc < 0 && rc != -EINTR) {
            fprintf(stderr, "[-] Network event polling failed\n");
            return 1;
        }
#else
        usleep(ctx->config.global.ringbuf_poll_timeout_ms * 1000);
#endif

        /* Quiet periodic evidence and logging-health flush. */
        clock_gettime(CLOCK_MONOTONIC, &tick);
#if FW_LOGGING
        if (tick.tv_sec - last_flush >= ctx->bus.log.window_sec) {
            event_bus_flush(&ctx->bus);
#else
        if (tick.tv_sec - last_flush >= ctx->config.global.stats_interval_sec) {
#ifndef NO_OBSERVABILITY
            stats_mgr_show(ctx->loader.stats_map_fd, 0);
#endif
#endif
            last_flush = tick.tv_sec;
        }
#if FW_ENGINE == FW_ENGINE_DUALMAP
        /* Reclaim the non-LRU established table independently of log cadence. */
        if (tick.tv_sec > last_gc) {
            conntrack_mgr_gc_sweep(ctx->loader.conntrack_map_fd);
            conntrack_mgr_gc_sweep(ctx->loader.syn_map_fd);
            last_gc = tick.tv_sec;
        }
#endif
    }

    return 0;
}

void firewall_ctx_reload(struct firewall_ctx *ctx)
{
    printf("\n[*] SIGHUP received: Reloading configuration and rules...\n");
    const char *cfg_file = ctx->opts.config_path ? ctx->opts.config_path : "config/firewall.yaml";
    if (access(cfg_file, F_OK) == 0) {
        struct firewall_config candidate = ctx->config;
        if (config_load_file(cfg_file, &candidate) < 0 || config_validate(&candidate) < 0) {
            fprintf(stderr, "[-] Invalid reload; keeping current configuration\n");
            return;
        }
        /* Hook and log destination changes require restart. */
#if FW_CONN_LIMIT
        if (candidate.connection_limit.enabled != ctx->config.connection_limit.enabled ||
            candidate.connection_limit.source_max != ctx->config.connection_limit.source_max ||
            strcmp(candidate.connection_limit.interfaces, ctx->config.connection_limit.interfaces)) {
            fprintf(stderr, "[-] Connection-limit changes require restart; keeping current configuration\n");
            return;
        }
#endif
#if FW_ANTI_SPOOF
        if (candidate.anti_spoof.enabled != ctx->config.anti_spoof.enabled ||
            strcmp(candidate.anti_spoof.path, ctx->config.anti_spoof.path)) {
            fprintf(stderr, "[-] Anti-spoof changes require restart; keeping current configuration\n");
            return;
        }
#endif
#if FW_RATE_LIMIT
        if (candidate.rate_limit.enabled != ctx->config.rate_limit.enabled ||
            strcmp(candidate.rate_limit.interfaces, ctx->config.rate_limit.interfaces) ||
            memcmp(&candidate.rate_limit.limits, &ctx->config.rate_limit.limits,
                   sizeof(candidate.rate_limit.limits))) {
            fprintf(stderr, "[-] Rate-limit changes require restart; keeping current configuration\n");
            return;
        }
#endif
        ctx->config.global = candidate.global;
        ctx->config.telemetry.aggregate_window_sec = candidate.telemetry.aggregate_window_sec;
#if FW_LOGGING
        ctx->bus.log.window_sec = candidate.telemetry.aggregate_window_sec;
        ctx->bus.log.max_bytes = (size_t)candidate.telemetry.max_file_mb * 1024 * 1024;
        ctx->bus.log.console = candidate.telemetry.console_events;
#endif
    }
    const char *rules_file = ctx->opts.rules_path ? ctx->opts.rules_path : "config/rules.yaml";
    if (rules_mgr_replace_file(ctx->loader.rules_map_fd, rules_file) < 0) {
        fprintf(stderr, "[-] Rule reload failed; see policy restoration diagnostics\n");
        return;
    }
    printf("[+] Configuration reload complete.\n");
}

void firewall_ctx_stop(struct firewall_ctx *ctx)
{
    if (ctx->opts.cmd != CMD_RUN) {
        bpf_loader_cleanup(&ctx->loader);
        return;
    }

    printf("\n\n[*] Shutting down firewall...\n");
#ifndef MINIMAL_OBSERVABILITY
    event_bus_cleanup(&ctx->bus);
#endif
    bpf_loader_cleanup(&ctx->loader);
    printf("[+] Detached and unloaded successfully.\n");
}
