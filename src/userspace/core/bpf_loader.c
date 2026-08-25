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

int bpf_loader_init(struct bpf_loader_ctx *ctx, const char *bpf_obj_path, const char *ifname)
{
    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->ifname, ifname, sizeof(ctx->ifname) - 1);

    ctx->ifindex = if_nametoindex(ifname);
    if (!ctx->ifindex) {
        fprintf(stderr, "[-] Error: Failed to resolve interface index for '%s': %s\n",
                ifname, strerror(errno));
        return -1;
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
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(ctx->obj, "xdp_firewall_prog");
    if (!prog) {
        fprintf(stderr, "[-] Error: Failed to locate 'xdp_firewall_prog' inside ELF object\n");
        bpf_object__close(ctx->obj);
        return -1;
    }

    ctx->prog_fd = bpf_program__fd(prog);

    /* Attempt Native Driver mode first, fall back to SKB (Generic) mode */
    ctx->xdp_flags = XDP_FLAGS_DRV_MODE;
    printf("[+] Attaching XDP program to %s (Native DRV mode)...\n", ifname);
    err = bpf_xdp_attach(ctx->ifindex, ctx->prog_fd, ctx->xdp_flags, NULL);
    if (err) {
        printf("[!] Native driver mode not supported on %s, falling back to Generic (SKB) mode...\n", ifname);
        ctx->xdp_flags = XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ctx->ifindex, ctx->prog_fd, ctx->xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "[-] Error: Failed to attach XDP to %s: %s\n", ifname, strerror(-err));
            bpf_object__close(ctx->obj);
            return -1;
        }
    }

    /* Retrieve Map FDs */
    ctx->stats_map_fd      = bpf_object__find_map_fd_by_name(ctx->obj, "stats_map");
    ctx->events_ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events_ringbuf");

    printf("[+] Successfully attached XDP program to %s (ifindex: %d)\n", ifname, ctx->ifindex);
    return 0;
}

void bpf_loader_cleanup(struct bpf_loader_ctx *ctx)
{
    if (ctx->ifindex > 0) {
        printf("\n[*] Detaching XDP program from %s (ifindex: %d)...\n", ctx->ifname, ctx->ifindex);
        bpf_xdp_detach(ctx->ifindex, ctx->xdp_flags, NULL);
        ctx->ifindex = 0;
    }

    if (ctx->obj) {
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
    }
}
