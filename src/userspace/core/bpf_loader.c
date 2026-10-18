#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <core/types.h>
#include "bpf_loader.h"
#include "config.h"
#if FW_CONN_LIMIT
#include <core/connection_limit.h>
#endif
#if FW_ANTI_SPOOF
#include "anti_spoof_mgr.h"
#endif

static int validate_object_profile(struct bpf_object *obj)
{
    struct bpf_map *ct = bpf_object__find_map_by_name(obj, "conntrack_map");
    struct bpf_map *rules = bpf_object__find_map_by_name(obj, "rules_map");
    const char *connection_maps[] = {"conn_limit_cfg", "conn_limit_src", "conn_limit_hint",
                                     "conn_limit_zero", "conn_limit_on", "conn_limit_tmp"};
    for (unsigned i = 0; i < sizeof(connection_maps) / sizeof(connection_maps[0]); i++) {
        if (!!bpf_object__find_map_by_name(obj, connection_maps[i]) != !!FW_CONN_LIMIT) {
            fprintf(stderr, "[-] Connection-limit maps do not match this build\n");
            return -1;
        }
    }
#if FW_CONN_LIMIT
    struct bpf_map *connection_sources = bpf_object__find_map_by_name(obj, "conn_limit_src");
    const __u32 connection_types[] = {BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_HASH,
        BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY};
    const __u32 connection_keys[] = {sizeof(__u32), sizeof(struct connection_source),
        sizeof(struct flow_key), sizeof(__u32), sizeof(__u32), sizeof(__u32)};
    const __u32 connection_values[] = {sizeof(__u32), sizeof(struct connection_source_slots),
        sizeof(struct connection_hint), sizeof(struct connection_zero_template), sizeof(__u32),
        sizeof(struct connection_scratch)};
    for (unsigned i = 0; i < sizeof(connection_maps) / sizeof(connection_maps[0]); i++) {
        struct bpf_map *map = bpf_object__find_map_by_name(obj, connection_maps[i]);
        if (bpf_map__type(map) != connection_types[i] ||
            bpf_map__key_size(map) != connection_keys[i] ||
            bpf_map__value_size(map) != connection_values[i]) return -1;
    }
    if (bpf_map__max_entries(connection_sources) != CONN_LIMIT_SOURCES) return -1;
#endif
#if FW_ANTI_SPOOF
    struct bpf_map *spoof = bpf_object__find_map_by_name(obj, "anti_spoof_prefix");
    struct bpf_map *scopes = bpf_object__find_map_by_name(obj, "anti_spoof_scopes");
    if (!spoof || !scopes || bpf_map__type(spoof) != BPF_MAP_TYPE_LPM_TRIE ||
        bpf_map__key_size(spoof) != sizeof(struct anti_spoof_key) ||
        bpf_map__value_size(spoof) != sizeof(__u32) ||
        bpf_map__type(scopes) != BPF_MAP_TYPE_HASH ||
        bpf_map__key_size(scopes) != sizeof(__u32) || bpf_map__value_size(scopes) != sizeof(__u32)) {
        fprintf(stderr, "[-] BPF anti-spoof maps do not match this build\n");
        return -1;
    }
#else
    if (bpf_object__find_map_by_name(obj, "anti_spoof_prefix") ||
        bpf_object__find_map_by_name(obj, "anti_spoof_scopes")) {
        fprintf(stderr, "[-] BPF object contains compiled-out anti-spoof maps\n");
        return -1;
    }
#endif
#if FW_RATE_LIMIT
    struct bpf_map *rate = bpf_object__find_map_by_name(obj, "syn_rate_config");
    struct bpf_map *sources = bpf_object__find_map_by_name(obj, "syn_rate_sources");
    struct bpf_map *total = bpf_object__find_map_by_name(obj, "syn_rate_total");
#else
    if (bpf_object__find_map_by_name(obj, "syn_rate_config") ||
        bpf_object__find_map_by_name(obj, "syn_rate_sources") ||
        bpf_object__find_map_by_name(obj, "syn_rate_total")) {
        fprintf(stderr, "[-] BPF object contains a compiled-out rate limiter\n");
        return -1;
    }
#endif
    if (!ct || !rules || bpf_map__key_size(ct) != sizeof(struct flow_key) ||
#if FW_RATE_LIMIT
        !rate || !sources || !total ||
        bpf_map__type(rate) != BPF_MAP_TYPE_HASH ||
        bpf_map__key_size(rate) != sizeof(__u32) ||
        bpf_map__value_size(rate) != sizeof(struct syn_rate_config) ||
        bpf_map__type(sources) != BPF_MAP_TYPE_HASH ||
        bpf_map__key_size(sources) != sizeof(struct rate_source_key) ||
        bpf_map__value_size(sources) != sizeof(struct rate_bucket) ||
        bpf_map__type(total) != BPF_MAP_TYPE_HASH ||
        bpf_map__key_size(total) != sizeof(__u32) ||
        bpf_map__value_size(total) != sizeof(struct rate_bucket) ||
#endif
        bpf_map__value_size(ct) != sizeof(struct flow_entry) ||
        bpf_map__value_size(rules) != sizeof(struct fw_rule) ||
        bpf_map__type(ct) != (FW_ENGINE == FW_ENGINE_DUALMAP ?
            BPF_MAP_TYPE_HASH : BPF_MAP_TYPE_LRU_HASH) ||
        !!bpf_object__find_map_by_name(obj, "flow_cache_map") != (FW_ENGINE == FW_ENGINE_FASTCACHE) ||
        !!bpf_object__find_map_by_name(obj, "ct_syn_map") != (FW_ENGINE == FW_ENGINE_DUALMAP) ||
        !!bpf_object__find_map_by_name(obj, "perf_map") != !!FW_TIMING ||
        !!bpf_object__find_map_by_name(obj, "events_ringbuf") != (FW_OBSERVABILITY == 0) ||
        !!bpf_object__find_map_by_name(obj, "stats_map") != (FW_OBSERVABILITY != 2)) {
        fprintf(stderr, "[-] BPF object does not match this control-plane build profile\n");
        return -1;
    }
    return 0;
}

static int map_matches(int fd, __u32 type, __u32 key_size, __u32 value_size)
{
    struct bpf_map_info info = {0};
    __u32 size = sizeof(info);
    return fd >= 0 && !bpf_obj_get_info_by_fd(fd, &info, &size) &&
           info.type == type && info.key_size == key_size && info.value_size == value_size;
}

static int attach_xdp(struct bpf_loader_ctx *ctx, struct iface_hook *ih)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->obj, "xdp_firewall_prog");
    if (!prog) {
        fprintf(stderr, "[-] Error: Failed to locate 'xdp_firewall_prog' inside ELF object\n");
        return -1;
    }

    ctx->xdp_prog_fd = bpf_program__fd(prog);

    /* Attempt Native Driver mode first, fall back to SKB (Generic) mode */
    ih->xdp_flags = XDP_FLAGS_DRV_MODE;
    printf("[+] Attaching XDP program to %s (Native DRV mode)...\n", ih->ifname);
    int err = bpf_xdp_attach(ih->ifindex, ctx->xdp_prog_fd, ih->xdp_flags, NULL);
    if (err) {
        printf("[!] Native driver mode not supported on %s, falling back to Generic (SKB) mode...\n", ih->ifname);
        ih->xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ih->ifindex, ctx->xdp_prog_fd, ih->xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "[-] Error: Failed to attach XDP to %s: %s\n", ih->ifname, strerror(-err));
            return -1;
        }
    }

    ih->xdp_attached = 1;
    ctx->xdp_attached = 1;
    printf("[+] Successfully attached XDP INGRESS program to %s (ifindex: %d)\n", ih->ifname, ih->ifindex);
    return 0;
}

static int ensure_tc_qdisc(struct iface_hook *ih)
{
    if (ih->tc_hook_created)
        return 0;

    struct bpf_tc_hook qdisc_hook;
    memset(&qdisc_hook, 0, sizeof(qdisc_hook));
    qdisc_hook.sz = sizeof(struct bpf_tc_hook);
    qdisc_hook.ifindex = ih->ifindex;
    qdisc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

    int err = bpf_tc_hook_create(&qdisc_hook);
    if (err && err != -EEXIST && errno != EEXIST) {
        fprintf(stderr, "[-] Warning: Failed to create TC clsact hook on %s: %s (%d)\n",
                ih->ifname, strerror(-err), err);
    } else {
        ih->tc_hook_created = 1;
    }
    return 0;
}

static int attach_tc_ingress(struct bpf_loader_ctx *ctx, struct iface_hook *ih)
{
    ensure_tc_qdisc(ih);

    struct bpf_program *prog_in = bpf_object__find_program_by_name(ctx->obj, "tc_ingress_prog");
    if (!prog_in) {
        fprintf(stderr, "[-] Error: Failed to locate 'tc_ingress_prog' inside ELF object\n");
        return -1;
    }

    memset(&ih->tc_hook_ingress, 0, sizeof(ih->tc_hook_ingress));
    ih->tc_hook_ingress.sz = sizeof(struct bpf_tc_hook);
    ih->tc_hook_ingress.ifindex = ih->ifindex;
    ih->tc_hook_ingress.attach_point = BPF_TC_INGRESS;

    memset(&ih->tc_opts_ingress, 0, sizeof(ih->tc_opts_ingress));
    ih->tc_opts_ingress.sz = sizeof(struct bpf_tc_opts);
    ih->tc_opts_ingress.prog_fd = bpf_program__fd(prog_in);

    printf("[+] Attaching TC INGRESS program to %s...\n", ih->ifname);
    int err = bpf_tc_attach(&ih->tc_hook_ingress, &ih->tc_opts_ingress);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to attach TC ingress to %s: %s (%d)\n",
                ih->ifname, strerror(-err), err);
        return -1;
    }
    ih->tc_ingress_attached = 1;
    ctx->tc_ingress_attached = 1;
    printf("[+] Successfully attached TC INGRESS program to %s (ifindex: %d)\n", ih->ifname, ih->ifindex);
    return 0;
}

static int attach_tc_egress(struct bpf_loader_ctx *ctx, struct iface_hook *ih)
{
    ensure_tc_qdisc(ih);

    struct bpf_program *prog_out = bpf_object__find_program_by_name(ctx->obj, "tc_egress_prog");
    if (!prog_out) {
        fprintf(stderr, "[-] Error: Failed to locate 'tc_egress_prog' inside ELF object\n");
        return -1;
    }

    memset(&ih->tc_hook_egress, 0, sizeof(ih->tc_hook_egress));
    ih->tc_hook_egress.sz = sizeof(struct bpf_tc_hook);
    ih->tc_hook_egress.ifindex = ih->ifindex;
    ih->tc_hook_egress.attach_point = BPF_TC_EGRESS;

    memset(&ih->tc_opts_egress, 0, sizeof(ih->tc_opts_egress));
    ih->tc_opts_egress.sz = sizeof(struct bpf_tc_opts);
    ih->tc_opts_egress.prog_fd = bpf_program__fd(prog_out);

    printf("[+] Attaching TC EGRESS program to %s...\n", ih->ifname);
    int err = bpf_tc_attach(&ih->tc_hook_egress, &ih->tc_opts_egress);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to attach TC egress to %s: %s (%d)\n",
                ih->ifname, strerror(-err), err);
        return -1;
    }
    ih->tc_egress_attached = 1;
    ctx->tc_egress_attached = 1;
    printf("[+] Successfully attached TC EGRESS program to %s (ifindex: %d)\n", ih->ifname, ih->ifindex);
    return 0;
}

#if FW_RATE_LIMIT
static int initialize_syn_limits(struct bpf_loader_ctx *ctx, const struct firewall_config *cfg)
{
    if (!cfg->rate_limit.enabled) return 0;
    int config_fd = bpf_object__find_map_fd_by_name(ctx->obj, "syn_rate_config");
    int total_fd = bpf_object__find_map_fd_by_name(ctx->obj, "syn_rate_total");
    char selected[256];
    snprintf(selected, sizeof(selected), "%s", cfg->rate_limit.interfaces[0] ?
             cfg->rate_limit.interfaces : cfg->interface);
    char *save = NULL;
    unsigned count = 0;
    for (char *name = strtok_r(selected, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
        while (*name == ' ' || *name == '\t') name++;
        size_t len = strlen(name);
        while (len && (name[len - 1] == ' ' || name[len - 1] == '\t')) name[--len] = '\0';
        __u32 index = 0;
        for (int i = 0; i < ctx->num_ifaces; i++)
            if (!strcmp(name, ctx->ifaces[i].ifname)) index = ctx->ifaces[i].ifindex;
        if (!index) {
            fprintf(stderr, "[-] Rate-limit interface '%s' is not an attached interface\n", name);
            return -1;
        }
        struct rate_bucket initial = {
            .credit = (__u64)cfg->rate_limit.limits.aggregate_burst * RATE_CREDIT_PER_PACKET,
        };
        if ((cfg->rate_limit.limits.aggregate_enabled &&
             bpf_map_update_elem(total_fd, &index, &initial, BPF_NOEXIST)) ||
            bpf_map_update_elem(config_fd, &index, &cfg->rate_limit.limits, BPF_NOEXIST)) {
            fprintf(stderr, "[-] Cannot initialize SYN limiter (duplicate scope or map error): %s\n", strerror(errno));
            return -1;
        }
        printf("[+] SYN protection selected on ingress %s\n", name);
        count++;
    }
    return count ? 0 : -1;
}
#endif

#if FW_CONN_LIMIT
static int initialize_connection_limits(struct bpf_loader_ctx *ctx, const struct firewall_config *cfg)
{
    if (!cfg->connection_limit.enabled) return 0;
    int fd = bpf_object__find_map_fd_by_name(ctx->obj, "conn_limit_cfg");
    char selected[256];
    snprintf(selected, sizeof(selected), "%s", cfg->connection_limit.interfaces[0] ?
             cfg->connection_limit.interfaces : cfg->interface);
    char *save = NULL;
    unsigned count = 0;
    for (char *name = strtok_r(selected, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
        while (*name == ' ' || *name == '\t') name++;
        size_t len = strlen(name);
        while (len && (name[len - 1] == ' ' || name[len - 1] == '\t')) name[--len] = '\0';
        __u32 index = 0;
        for (int i = 0; i < ctx->num_ifaces; i++)
            if (!strcmp(name, ctx->ifaces[i].ifname)) index = ctx->ifaces[i].ifindex;
        if (!index || bpf_map_update_elem(fd, &index, &cfg->connection_limit.source_max, BPF_NOEXIST)) {
            fprintf(stderr, "[-] Invalid/duplicate connection-limit interface or map failure: %s\n", name);
            return -1;
        }
        printf("[+] TCP connection cap selected on ingress %s\n", name);
        count++;
    }
    __u32 zero = 0, enabled = 1;
    int on_fd = bpf_object__find_map_fd_by_name(ctx->obj, "conn_limit_on");
    return count && !bpf_map_update_elem(on_fd, &zero, &enabled, BPF_ANY) ? 0 : -1;
}
#endif

int bpf_loader_init(struct bpf_loader_ctx *ctx, const char *bpf_obj_path, const struct firewall_config *cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->flow_cache_map_fd = ctx->syn_map_fd = ctx->perf_map_fd = -1;
    ctx->rules_map_fd = ctx->conntrack_map_fd = ctx->stats_map_fd = ctx->events_ringbuf_fd = -1;
    snprintf(ctx->ifname, sizeof(ctx->ifname), "%s", cfg->interface);
    ctx->direction = cfg->direction;
    ctx->mode = cfg->mode;

    /* Parse comma-separated list of interfaces (e.g. "veth1,veth2") */
    char iflist[256];
    snprintf(iflist, sizeof(iflist), "%s", cfg->interface);
    char *saveptr = NULL;
    char *tok = strtok_r(iflist, ",", &saveptr);
    ctx->num_ifaces = 0;

    while (tok && ctx->num_ifaces < MAX_LOADER_IFACES) {
        /* trim whitespace */
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';

        if (strlen(tok) > 0) {
            struct iface_hook *ih = &ctx->ifaces[ctx->num_ifaces];
            memset(ih, 0, sizeof(*ih));
            snprintf(ih->ifname, sizeof(ih->ifname), "%s", tok);
            ih->ifindex = if_nametoindex(tok);
            if (!ih->ifindex) {
                fprintf(stderr, "[-] Error: Failed to resolve interface index for '%s': %s\n",
                        tok, strerror(errno));
                return -1;
            }
            ctx->num_ifaces++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    if (ctx->num_ifaces == 0) {
        fprintf(stderr, "[-] Error: No valid interfaces specified\n");
        return -1;
    }

    ctx->ifindex = ctx->ifaces[0].ifindex;

    /* Auto-switch mode if pure XDP is requested for egress-only */
    if (ctx->mode == ATTACH_MODE_XDP && ctx->direction == TRAFFIC_DIR_EGRESS) {
        printf("[!] Notice: XDP cannot handle Egress. Switching to TC Egress for %s.\n", ctx->ifname);
        ctx->mode = ATTACH_MODE_TC;
    }

    printf("[+] Opening BPF object '%s'...\n", bpf_obj_path);
    ctx->obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!ctx->obj || libbpf_get_error(ctx->obj)) {
        fprintf(stderr, "[-] Error: Failed to open BPF ELF file: %s\n", strerror(errno));
        return -1;
    }
    if (validate_object_profile(ctx->obj)) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }

    printf("[+] Loading BPF program into kernel...\n");
    int err = bpf_object__load(ctx->obj);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to load BPF object: %s (%d)\n", strerror(-err), err);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }

    /* Reserve pins before attaching: never replace another running daemon's
     * maps or leave a live program attached after a pin failure. */
    if (bpf_loader_pin_maps(ctx)) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }

    /* Retrieve Map FDs before policy initialization and attachment. */
    ctx->stats_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "stats_map");
    ctx->events_ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events_ringbuf");
    ctx->rules_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "rules_map");
    ctx->conntrack_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "conntrack_map");
    ctx->flow_cache_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "flow_cache_map");
    ctx->syn_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "ct_syn_map");
    ctx->perf_map_fd = bpf_object__find_map_fd_by_name(ctx->obj, "perf_map");
    if (ctx->rules_map_fd < 0) {
        fprintf(stderr, "[-] Required rules_map missing; refusing attachment\n");
        bpf_loader_cleanup(ctx);
        return -1;
    }
#if FW_CONN_LIMIT
    if (initialize_connection_limits(ctx, cfg)) {
        bpf_loader_cleanup(ctx);
        return -1;
    }
#endif
#if FW_ANTI_SPOOF
    if (anti_spoof_initialize(ctx, cfg)) {
        bpf_loader_cleanup(ctx);
        return -1;
    }
#endif
#if FW_RATE_LIMIT
    if (initialize_syn_limits(ctx, cfg)) {
        bpf_loader_cleanup(ctx);
        return -1;
    }
#endif
    return 0;
}

int bpf_loader_attach(struct bpf_loader_ctx *ctx)
{
    if (!ctx->obj || ctx->rules_map_fd < 0) return -1;
    /* Attach only after the caller has initialized and verified policy. */
    for (int i = 0; i < ctx->num_ifaces; i++) {
        struct iface_hook *ih = &ctx->ifaces[i];

        if (ctx->mode == ATTACH_MODE_HYBRID) {
            /* HYBRID: XDP for Ingress, TC for Egress */
            if (ctx->direction == TRAFFIC_DIR_INGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
                if (attach_xdp(ctx, ih) < 0) {
                    bpf_loader_cleanup(ctx);
                    return -1;
                }
            }
            if (ctx->direction == TRAFFIC_DIR_EGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
                if (attach_tc_egress(ctx, ih) < 0) {
                    bpf_loader_cleanup(ctx);
                    return -1;
                }
            }
        } else if (ctx->mode == ATTACH_MODE_TC) {
            /* Pure TC: TC Ingress + TC Egress */
            if (ctx->direction == TRAFFIC_DIR_INGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
                if (attach_tc_ingress(ctx, ih) < 0) {
                    bpf_loader_cleanup(ctx);
                    return -1;
                }
            }
            if (ctx->direction == TRAFFIC_DIR_EGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
                if (attach_tc_egress(ctx, ih) < 0) {
                    bpf_loader_cleanup(ctx);
                    return -1;
                }
            }
        } else {
            /* Pure XDP (Ingress only) */
            if (attach_xdp(ctx, ih) < 0) {
                bpf_loader_cleanup(ctx);
                return -1;
            }
        }
    }

    return 0;
}

int bpf_loader_pin_maps(struct bpf_loader_ctx *ctx)
{
    if (!ctx->obj) return -1;

    int err = bpf_object__pin_maps(ctx->obj, BPF_FS_PATH);
    if (err) {
        fprintf(stderr, "[-] Cannot reserve firewall map pins: %s. Stop the existing daemon or clean stale pins first.\n", strerror(-err));
        return -1;
    }
    ctx->maps_pinned = 1;
    return 0;
}

int bpf_loader_open_pinned_maps(struct bpf_loader_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->rules_map_fd = bpf_obj_get(MAP_PIN_RULES);
    ctx->conntrack_map_fd = bpf_obj_get(MAP_PIN_CONNTRACK);
    ctx->flow_cache_map_fd = bpf_obj_get(MAP_PIN_CACHE);
    ctx->syn_map_fd = bpf_obj_get(MAP_PIN_CONNTRACK_SYN);
    ctx->perf_map_fd = bpf_obj_get(MAP_PIN_PERF);
    ctx->stats_map_fd = bpf_obj_get(MAP_PIN_STATS);
    ctx->events_ringbuf_fd = bpf_obj_get(MAP_PIN_EVENTS);

    int rate_fd = bpf_obj_get(BPF_FS_PATH "/syn_rate_config");
    int has_rate = rate_fd >= 0;
#if FW_RATE_LIMIT
    int rate_match = map_matches(rate_fd, BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(struct syn_rate_config));
#else
    int rate_match = !has_rate;
#endif
    if (rate_fd >= 0) close(rate_fd);
    int spoof_fd = bpf_obj_get(BPF_FS_PATH "/anti_spoof_prefix");
    int has_spoof = spoof_fd >= 0;
    if (spoof_fd >= 0) close(spoof_fd);
    int connection_fd = bpf_obj_get(BPF_FS_PATH "/conn_limit_src");
    int has_connection_limit = connection_fd >= 0;
#if FW_CONN_LIMIT
    int connection_match = map_matches(connection_fd, BPF_MAP_TYPE_HASH,
        sizeof(struct connection_source), sizeof(struct connection_source_slots));
#else
    int connection_match = !has_connection_limit;
#endif
    if (connection_fd >= 0) close(connection_fd);
    struct bpf_map_info stats_info = {0};
    __u32 stats_size = sizeof(stats_info);
    int stats_match = ctx->stats_map_fd < 0 ||
        (!bpf_obj_get_info_by_fd(ctx->stats_map_fd, &stats_info, &stats_size) &&
         stats_info.max_entries == STAT_MAX_COUNTERS);

    if (!map_matches(ctx->rules_map_fd, BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(struct fw_rule)) ||
        has_rate != !!FW_RATE_LIMIT || !rate_match || has_spoof != !!FW_ANTI_SPOOF || !stats_match ||
        has_connection_limit != !!FW_CONN_LIMIT || !connection_match ||
        !map_matches(ctx->conntrack_map_fd, FW_ENGINE == FW_ENGINE_DUALMAP ? BPF_MAP_TYPE_HASH : BPF_MAP_TYPE_LRU_HASH,
                     sizeof(struct flow_key), sizeof(struct flow_entry)) ||
        (ctx->flow_cache_map_fd >= 0) != (FW_ENGINE == FW_ENGINE_FASTCACHE) ||
        (ctx->syn_map_fd >= 0) != (FW_ENGINE == FW_ENGINE_DUALMAP) ||
        (ctx->perf_map_fd >= 0) != !!FW_TIMING ||
        (ctx->events_ringbuf_fd >= 0) != (FW_OBSERVABILITY == 0) ||
        (ctx->stats_map_fd >= 0) != (FW_OBSERVABILITY != 2)) {
        fprintf(stderr, "[-] Pinned maps are missing or belong to a different build profile\n");
        bpf_loader_cleanup(ctx);
        return -1;
    }
    return 0;
}

void bpf_loader_cleanup(struct bpf_loader_ctx *ctx)
{
    for (int i = 0; i < ctx->num_ifaces; i++) {
        struct iface_hook *ih = &ctx->ifaces[i];

        if (ih->xdp_attached && ih->ifindex > 0) {
            printf("\n[*] Detaching XDP program from %s (ifindex: %d)...\n", ih->ifname, ih->ifindex);
            bpf_xdp_detach(ih->ifindex, ih->xdp_flags, NULL);
            ih->xdp_attached = 0;
        }

        if (ih->tc_ingress_attached) {
            printf("\n[*] Detaching TC INGRESS program from %s...\n", ih->ifname);
            bpf_tc_detach(&ih->tc_hook_ingress, &ih->tc_opts_ingress);
            ih->tc_ingress_attached = 0;
        }

        if (ih->tc_egress_attached) {
            printf("\n[*] Detaching TC EGRESS program from %s...\n", ih->ifname);
            bpf_tc_detach(&ih->tc_hook_egress, &ih->tc_opts_egress);
            ih->tc_egress_attached = 0;
        }

        if (ih->tc_hook_created) {
            struct bpf_tc_hook qdisc_hook;
            memset(&qdisc_hook, 0, sizeof(qdisc_hook));
            qdisc_hook.sz = sizeof(struct bpf_tc_hook);
            qdisc_hook.ifindex = ih->ifindex;
            qdisc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
            bpf_tc_hook_destroy(&qdisc_hook);
            ih->tc_hook_created = 0;
        }
    }

    ctx->xdp_attached = 0;
    ctx->tc_ingress_attached = 0;
    ctx->tc_egress_attached = 0;

    if (ctx->maps_pinned && ctx->obj) {
        bpf_object__unpin_maps(ctx->obj, BPF_FS_PATH);
        ctx->maps_pinned = 0;
    }

    if (ctx->obj) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
    } else {
        int *fds[] = {&ctx->rules_map_fd, &ctx->conntrack_map_fd,
                      &ctx->flow_cache_map_fd, &ctx->syn_map_fd,
                      &ctx->perf_map_fd, &ctx->stats_map_fd, &ctx->events_ringbuf_fd};
        for (unsigned i = 0; i < sizeof(fds) / sizeof(*fds); i++) {
            if (*fds[i] >= 0) close(*fds[i]);
            *fds[i] = -1;
        }
    }
}
