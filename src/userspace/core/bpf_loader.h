#ifndef __CORE_BPF_LOADER_H__
#define __CORE_BPF_LOADER_H__

#include <linux/types.h>
#include <bpf/libbpf.h>

struct bpf_loader_ctx {
    struct bpf_object *obj;
    int prog_fd;
    int ifindex;
    __u32 xdp_flags;
    char ifname[32];

    /* Map FDs */
    int stats_map_fd;
    int events_ringbuf_fd;
};

struct firewall_config;

/* Load BPF object, attach XDP program to interface, and fetch map FDs */
int bpf_loader_init(struct bpf_loader_ctx *ctx, const char *bpf_obj_path, const char *ifname);

/* Detach XDP program from interface and close BPF object */
void bpf_loader_cleanup(struct bpf_loader_ctx *ctx);

#endif /* __CORE_BPF_LOADER_H__ */
