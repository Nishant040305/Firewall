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

static int attach_xdp(struct bpf_loader_ctx *ctx)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->obj, "xdp_firewall_prog");
    if (!prog) {
        fprintf(stderr, "[-] Error: Failed to locate 'xdp_firewall_prog' inside ELF object\n");
        return -1;
    }

    ctx->xdp_prog_fd = bpf_program__fd(prog);

    /* Attempt Native Driver mode first, fall back to SKB (Generic) mode */
    ctx->xdp_flags = XDP_FLAGS_DRV_MODE;
    printf("[+] Attaching XDP program to %s (Native DRV mode)...\n", ctx->ifname);
    int err = bpf_xdp_attach(ctx->ifindex, ctx->xdp_prog_fd, ctx->xdp_flags, NULL);
    if (err) {
        printf("[!] Native driver mode not supported on %s, falling back to Generic (SKB) mode...\n", ctx->ifname);
        ctx->xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ctx->ifindex, ctx->xdp_prog_fd, ctx->xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "[-] Error: Failed to attach XDP to %s: %s\n", ctx->ifname, strerror(-err));
            return -1;
        }
    }

    ctx->xdp_attached = 1;
    printf("[+] Successfully attached XDP INGRESS program to %s (ifindex: %d)\n", ctx->ifname, ctx->ifindex);
    return 0;
}

static int ensure_tc_qdisc(struct bpf_loader_ctx *ctx)
{
    if (ctx->tc_hook_created)
        return 0;

    struct bpf_tc_hook qdisc_hook;
    memset(&qdisc_hook, 0, sizeof(qdisc_hook));
    qdisc_hook.sz = sizeof(struct bpf_tc_hook);
    qdisc_hook.ifindex = ctx->ifindex;
    qdisc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

    int err = bpf_tc_hook_create(&qdisc_hook);
    if (err && err != -EEXIST && errno != EEXIST) {
        fprintf(stderr, "[-] Warning: Failed to create TC clsact hook on %s: %s (%d)\n",
                ctx->ifname, strerror(-err), err);
    } else {
        ctx->tc_hook_created = 1;
    }
    return 0;
}

static int attach_tc_ingress(struct bpf_loader_ctx *ctx)
{
    ensure_tc_qdisc(ctx);

    struct bpf_program *prog_in = bpf_object__find_program_by_name(ctx->obj, "tc_ingress_prog");
    if (!prog_in) {
        fprintf(stderr, "[-] Error: Failed to locate 'tc_ingress_prog' inside ELF object\n");
        return -1;
    }

    memset(&ctx->tc_hook_ingress, 0, sizeof(ctx->tc_hook_ingress));
    ctx->tc_hook_ingress.sz = sizeof(struct bpf_tc_hook);
    ctx->tc_hook_ingress.ifindex = ctx->ifindex;
    ctx->tc_hook_ingress.attach_point = BPF_TC_INGRESS;

    memset(&ctx->tc_opts_ingress, 0, sizeof(ctx->tc_opts_ingress));
    ctx->tc_opts_ingress.sz = sizeof(struct bpf_tc_opts);
    ctx->tc_opts_ingress.prog_fd = bpf_program__fd(prog_in);

    printf("[+] Attaching TC INGRESS program to %s...\n", ctx->ifname);
    int err = bpf_tc_attach(&ctx->tc_hook_ingress, &ctx->tc_opts_ingress);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to attach TC ingress to %s: %s (%d)\n",
                ctx->ifname, strerror(-err), err);
        return -1;
    }
    ctx->tc_ingress_attached = 1;
    printf("[+] Successfully attached TC INGRESS program to %s (ifindex: %d)\n", ctx->ifname, ctx->ifindex);
    return 0;
}

static int attach_tc_egress(struct bpf_loader_ctx *ctx)
{
    ensure_tc_qdisc(ctx);

    struct bpf_program *prog_out = bpf_object__find_program_by_name(ctx->obj, "tc_egress_prog");
    if (!prog_out) {
        fprintf(stderr, "[-] Error: Failed to locate 'tc_egress_prog' inside ELF object\n");
        return -1;
    }

    memset(&ctx->tc_hook_egress, 0, sizeof(ctx->tc_hook_egress));
    ctx->tc_hook_egress.sz = sizeof(struct bpf_tc_hook);
    ctx->tc_hook_egress.ifindex = ctx->ifindex;
    ctx->tc_hook_egress.attach_point = BPF_TC_EGRESS;

    memset(&ctx->tc_opts_egress, 0, sizeof(ctx->tc_opts_egress));
    ctx->tc_opts_egress.sz = sizeof(struct bpf_tc_opts);
    ctx->tc_opts_egress.prog_fd = bpf_program__fd(prog_out);

    printf("[+] Attaching TC EGRESS program to %s...\n", ctx->ifname);
    int err = bpf_tc_attach(&ctx->tc_hook_egress, &ctx->tc_opts_egress);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to attach TC egress to %s: %s (%d)\n",
                ctx->ifname, strerror(-err), err);
        return -1;
    }
    ctx->tc_egress_attached = 1;
    printf("[+] Successfully attached TC EGRESS program to %s (ifindex: %d)\n", ctx->ifname, ctx->ifindex);
    return 0;
}

int bpf_loader_init(struct bpf_loader_ctx *ctx, const char *bpf_obj_path, const struct firewall_config *cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    snprintf(ctx->ifname, sizeof(ctx->ifname), "%s", cfg->interface);
    ctx->direction = cfg->direction;
    ctx->mode = cfg->mode;

    ctx->ifindex = if_nametoindex(cfg->interface);
    if (!ctx->ifindex) {
        fprintf(stderr, "[-] Error: Failed to resolve interface index for '%s': %s\n",
                cfg->interface, strerror(errno));
        return -1;
    }

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

    printf("[+] Loading BPF program into kernel...\n");
    int err = bpf_object__load(ctx->obj);
    if (err) {
        fprintf(stderr, "[-] Error: Failed to load BPF object: %s (%d)\n", strerror(-err), err);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }

    /* Attach according to chosen mode */
    if (ctx->mode == ATTACH_MODE_HYBRID) {
        /* HYBRID: XDP for Ingress, TC for Egress */
        if (ctx->direction == TRAFFIC_DIR_INGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
            if (attach_xdp(ctx) < 0) {
                bpf_loader_cleanup(ctx);
                return -1;
            }
        }
        if (ctx->direction == TRAFFIC_DIR_EGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
            if (attach_tc_egress(ctx) < 0) {
                bpf_loader_cleanup(ctx);
                return -1;
            }
        }
    } else if (ctx->mode == ATTACH_MODE_TC) {
        /* Pure TC: TC Ingress + TC Egress */
        if (ctx->direction == TRAFFIC_DIR_INGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
            if (attach_tc_ingress(ctx) < 0) {
                bpf_loader_cleanup(ctx);
                return -1;
            }
        }
        if (ctx->direction == TRAFFIC_DIR_EGRESS || ctx->direction == TRAFFIC_DIR_BOTH) {
            if (attach_tc_egress(ctx) < 0) {
                bpf_loader_cleanup(ctx);
                return -1;
            }
        }
    } else {
        /* Pure XDP (Ingress only) */
        if (attach_xdp(ctx) < 0) {
            bpf_loader_cleanup(ctx);
            return -1;
        }
    }

    /* Retrieve Map FDs */
    ctx->stats_map_fd      = bpf_object__find_map_fd_by_name(ctx->obj, "stats_map");
    ctx->events_ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events_ringbuf");

    return 0;
}

void bpf_loader_cleanup(struct bpf_loader_ctx *ctx)
{
    if (ctx->xdp_attached && ctx->ifindex > 0) {
        printf("\n[*] Detaching XDP program from %s (ifindex: %d)...\n", ctx->ifname, ctx->ifindex);
        bpf_xdp_detach(ctx->ifindex, ctx->xdp_flags, NULL);
        ctx->xdp_attached = 0;
    }

    if (ctx->tc_ingress_attached) {
        printf("\n[*] Detaching TC INGRESS program from %s...\n", ctx->ifname);
        bpf_tc_detach(&ctx->tc_hook_ingress, &ctx->tc_opts_ingress);
        ctx->tc_ingress_attached = 0;
    }

    if (ctx->tc_egress_attached) {
        printf("\n[*] Detaching TC EGRESS program from %s...\n", ctx->ifname);
        bpf_tc_detach(&ctx->tc_hook_egress, &ctx->tc_opts_egress);
        ctx->tc_egress_attached = 0;
    }

    if (ctx->tc_hook_created) {
        struct bpf_tc_hook qdisc_hook;
        memset(&qdisc_hook, 0, sizeof(qdisc_hook));
        qdisc_hook.sz = sizeof(struct bpf_tc_hook);
        qdisc_hook.ifindex = ctx->ifindex;
        qdisc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
        bpf_tc_hook_destroy(&qdisc_hook);
        ctx->tc_hook_created = 0;
    }

    if (ctx->obj) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
    }
}
