#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cli.h"

void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS] [interface]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --interface <iface>      Network interface to attach firewall (e.g. eth0, veth_server)\n");
    printf("  -d, --direction <dir>        Traffic direction: in, out, both (default: both)\n");
    printf("  -m, --mode <mode>            Hook mode: hybrid, tc, xdp (default: hybrid)\n");
    printf("                               - hybrid: XDP handles Ingress (RX), TC handles Egress (TX)\n");
    printf("                               - tc:     TC handles both Ingress and Egress\n");
    printf("                               - xdp:    XDP handles Ingress only\n");
    printf("  -c, --config <file>          Path to runtime configuration YAML (default: config/firewall.yaml)\n");
    printf("  -h, --help                   Show this help message\n\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0                     # Monitor both: XDP (ingress) + TC (egress)\n", prog_name);
    printf("  sudo %s -i eth0 -d both -m hybrid   # Explicit hybrid mode\n", prog_name);
    printf("  sudo %s -i eth0 -d in -m xdp        # Monitor incoming only via XDP\n", prog_name);
    printf("  sudo %s -i eth0 -d out              # Monitor outgoing only via TC egress\n", prog_name);
}

int parse_cli_args(int argc, char **argv, struct firewall_options *opts)
{
    memset(opts, 0, sizeof(*opts));

    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"direction",  required_argument, 0, 'd'},
        {"mode",       required_argument, 0, 'm'},
        {"config",     required_argument, 0, 'c'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:d:m:c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            opts->iface = optarg;
            break;
        case 'd':
            opts->direction = optarg;
            break;
        case 'm':
            opts->mode = optarg;
            break;
        case 'c':
            opts->config_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    /* Positional fallback for arguments (config file or interface) */
    if (optind < argc) {
        const char *arg = argv[optind];
        if (!opts->config_path && (strstr(arg, ".yaml") || strstr(arg, ".yml"))) {
            opts->config_path = arg;
        } else if (!opts->iface) {
            opts->iface = arg;
        }
    }

    return 0;
}
