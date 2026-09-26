#ifndef __CORE_BPF_LOADER_H__
#define __CORE_BPF_LOADER_H__

#include <linux/types.h>
#include <bpf/libbpf.h>
#include "config.h"

#define MAX_LOADER_IFACES 16

struct iface_hook {
    char ifname[64];
    int ifindex;
    int xdp_attached;
    __u32 xdp_flags;
    int tc_ingress_attached;
    int tc_egress_attached;
    int tc_hook_created;
    struct bpf_tc_hook tc_hook_ingress;
    struct bpf_tc_opts tc_opts_ingress;
    struct bpf_tc_hook tc_hook_egress;
    struct bpf_tc_opts tc_opts_egress;
};

struct bpf_loader_ctx {
    struct bpf_object *obj;
    int ifindex;
    char ifname[256];
    enum attach_mode mode;
    enum traffic_direction direction;

    int num_ifaces;
    struct iface_hook ifaces[MAX_LOADER_IFACES];

    /* XDP */
    int xdp_prog_fd;
    __u32 xdp_flags;
    int xdp_attached;

    /* TC Ingress */
    struct bpf_tc_hook tc_hook_ingress;
    struct bpf_tc_opts tc_opts_ingress;
    int tc_ingress_attached;

    /* TC Egress */
    struct bpf_tc_hook tc_hook_egress;
    struct bpf_tc_opts tc_opts_egress;
    int tc_egress_attached;

    int tc_hook_created;

    /* Map FDs */
    int stats_map_fd;
    int events_ringbuf_fd;
    int rules_map_fd;
    int conntrack_map_fd;
    int flow_cache_map_fd;
};

/* Load BPF object, attach programs (TC or XDP, Ingress / Egress / Both), and fetch map FDs */
int bpf_loader_init(struct bpf_loader_ctx *ctx, const char *bpf_obj_path, const struct firewall_config *cfg);

/* Pin maps to bpffs */
int bpf_loader_pin_maps(struct bpf_loader_ctx *ctx);

/* Open pinned maps from bpffs for CLI management */
int bpf_loader_open_pinned_maps(struct bpf_loader_ctx *ctx);

/* Detach all attached BPF programs from interface and close BPF object */
void bpf_loader_cleanup(struct bpf_loader_ctx *ctx);

#endif /* __CORE_BPF_LOADER_H__ */
