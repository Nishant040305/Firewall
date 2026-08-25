#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cli.h"

void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS] [interface]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --interface <iface>    Network interface to attach XDP firewall (e.g. eth0, veth_server)\n");
    printf("  -c, --config <file>        Path to runtime configuration YAML (default: config/firewall.yaml)\n");
    printf("  -h, --help                 Show this help message\n\n");
    printf("Example:\n");
    printf("  sudo %s -i veth_server\n", prog_name);
}

int parse_cli_args(int argc, char **argv, struct firewall_options *opts)
{
    memset(opts, 0, sizeof(*opts));

    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"config",     required_argument, 0, 'c'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            opts->iface = optarg;
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

    /* Positional fallback for interface argument */
    if (!opts->iface && optind < argc) {
        opts->iface = argv[optind];
    }

    return 0;
}
