#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* Baseline B: Clean XDP Pass program for measuring XDP driver/datapath overhead */
SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}
