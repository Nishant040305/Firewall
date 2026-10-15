#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "cli.h"
#include <core/constants.h>
#include "../utils/ip_utils.h"

void print_usage(const char *prog_name)
{
    printf("========================================================================================\n");
    printf("               FIREWALLCTL - Stateful eBPF/XDP Firewall Control Utility                 \n");
    printf("========================================================================================\n");
    printf("Usage:\n");
    printf("Build: engine=%d timing=%d logging=%d observability=%d\n",
           FW_ENGINE, FW_TIMING, FW_LOGGING, FW_OBSERVABILITY);
#if FW_TIMING
    printf("  %s perf show [--json] | perf reset             # Component timing\n", prog_name);
#endif
    printf("  %s [OPTIONS] [interface]                      # Start firewall daemon & monitor\n", prog_name);
    printf("  %s rule list                                  # List dynamic firewall rules\n", prog_name);
    printf("  %s rule add [RULE OPTIONS]                    # Add a new firewall rule\n", prog_name);
    printf("  %s rule del <rule_id>                         # Delete a rule by ID\n", prog_name);
    printf("  %s rule flush                                 # Flush all rules\n", prog_name);
    printf("  %s rule load <rules.yaml>                     # Load rules from YAML file\n", prog_name);
    printf("  %s conntrack list                             # View active connection state table\n", prog_name);
    printf("  %s conntrack flush                            # Flush active connection states\n", prog_name);
    printf("  %s stats show [--json]                        # Display packet & connection stats\n", prog_name);
    printf("  %s stats reset                                # Reset statistics counters\n\n", prog_name);

    printf("Daemon Options:\n");
    printf("  -i, --interface <iface>      Network interface to attach firewall (e.g. eth0, veth_server)\n");
    printf("  -d, --direction <dir>        Traffic direction: in, out, both (default: both)\n");
    printf("  -m, --mode <mode>            Hook mode: hybrid, tc, xdp (default: hybrid)\n");
    printf("  -c, --config <file>          Path to runtime config YAML (default: config/firewall.yaml)\n");
    printf("  -r, --rules <file>           Path to rules YAML (default: config/rules.yaml)\n");
    printf("  -h, --help                   Show this help message\n\n");

    printf("Rule Add Options:\n");
    printf("  --action <allow|drop>        Rule action (default: allow)\n");
    printf("  --proto <tcp|udp|icmp|icmpv6|any> IP protocol\n");
    printf("  --family <ipv4|ipv6|any>     Address family (inferred from addresses)\n");
    printf("  --src <ip/cidr>              Source IP / CIDR\n");
    printf("  --dst <ip/cidr>              Destination IP / CIDR\n");
    printf("  --sport <port|range>         Source port or range (e.g. 80, 1000-2000)\n");
    printf("  --dport <port|range>         Destination port or range (e.g. 80, 5201)\n");
    printf("  --desc <text>                Description note\n\n");

    printf("Examples:\n");
    printf("  sudo %s -i eth0                               # Attach and monitor traffic on eth0\n", prog_name);
    printf("  sudo %s rule add --proto tcp --dport 80 --action allow --desc 'HTTP Web'\n", prog_name);
    printf("  sudo %s rule add --proto tcp --dport 5201 --action allow --desc 'iperf3'\n", prog_name);
    printf("  sudo %s rule add --proto icmp --action allow --desc 'ICMP Ping'\n", prog_name);
    printf("  sudo %s rule list\n", prog_name);
    printf("  sudo %s conntrack list\n", prog_name);
    printf("  sudo %s stats show\n", prog_name);
    printf("========================================================================================\n");
}

int parse_cli_args(int argc, char **argv, struct firewall_options *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->cmd = CMD_RUN;
    opts->new_rule.action = ACTION_PASS;
    opts->new_rule.flags = RULE_FLAG_ACTIVE;

    if (argc > 1) {
#if FW_TIMING
        if (!strcmp(argv[1], "perf")) {
            if (argc == 2 || !strcmp(argv[2], "show")) {
                opts->cmd = CMD_PERF_SHOW;
                opts->json_output = argc > 3 && !strcmp(argv[3], "--json");
                return 0;
            }
            if (!strcmp(argv[2], "reset")) {
                opts->cmd = CMD_PERF_RESET;
                return 0;
            }
            return -1;
        }
#endif
        if (strcmp(argv[1], "rule") == 0) {
            if (argc == 2 || strcmp(argv[2], "list") == 0) {
                opts->cmd = CMD_RULE_LIST;
                return 0;
            } else if (strcmp(argv[2], "flush") == 0) {
                opts->cmd = CMD_RULE_FLUSH;
                return 0;
            } else if (strcmp(argv[2], "del") == 0) {
                opts->cmd = CMD_RULE_DEL;
                if (argc > 3) {
                    opts->del_rule_id = atoi(argv[3]);
                }
                return 0;
            } else if (strcmp(argv[2], "load") == 0) {
                opts->cmd = CMD_RULE_LOAD;
                opts->rules_path = (argc > 3) ? argv[3] : "config/rules.yaml";
                return 0;
            } else if (strcmp(argv[2], "add") == 0) {
                opts->cmd = CMD_RULE_ADD;
                for (int i = 3; i < argc; i++) {
                    if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) {
                        const char *action = argv[++i];
                        if (!strcasecmp(action, "drop")) opts->new_rule.action = ACTION_DROP;
                        else if (!strcasecmp(action, "allow") || !strcasecmp(action, "pass")) opts->new_rule.action = ACTION_PASS;
                        else return -1;
                    } else if (strcmp(argv[i], "--proto") == 0 && i + 1 < argc) {
                        opts->new_rule.flags |= RULE_FLAG_PROTO;
                        const char *p = argv[++i];
                        if (strcasecmp(p, "tcp") == 0) opts->new_rule.proto = PROTO_TCP;
                        else if (strcasecmp(p, "udp") == 0) opts->new_rule.proto = PROTO_UDP;
                        else if (strcasecmp(p, "icmp") == 0) opts->new_rule.proto = PROTO_ICMP;
                        else if (strcasecmp(p, "icmpv6") == 0) opts->new_rule.proto = PROTO_ICMPV6;
                        else if (strcasecmp(p, "any") == 0) opts->new_rule.proto = PROTO_ANY;
                        else return -1;
                    } else if (strcmp(argv[i], "--family") == 0 && i + 1 < argc) {
                        if (rule_set_family(&opts->new_rule, argv[++i])) return -1;
                    } else if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) {
                        if (rule_set_address(&opts->new_rule, argv[++i], 1)) return -1;
                    } else if (strcmp(argv[i], "--dst") == 0 && i + 1 < argc) {
                        if (rule_set_address(&opts->new_rule, argv[++i], 0)) return -1;
                    } else if (strcmp(argv[i], "--dport") == 0 && i + 1 < argc) {
                        if (parse_port_range(argv[++i], &opts->new_rule.dst_port_min,
                                             &opts->new_rule.dst_port_max)) return -1;
                        opts->new_rule.flags |= RULE_FLAG_DST_PORT;
                    } else if (strcmp(argv[i], "--sport") == 0 && i + 1 < argc) {
                        if (parse_port_range(argv[++i], &opts->new_rule.src_port_min,
                                             &opts->new_rule.src_port_max)) return -1;
                        opts->new_rule.flags |= RULE_FLAG_SRC_PORT;
                    } else if (strcmp(argv[i], "--desc") == 0 && i + 1 < argc) {
                        snprintf(opts->new_rule.description, sizeof(opts->new_rule.description), "%s", argv[++i]);
                    } else {
                        fprintf(stderr, "Invalid or incomplete rule option: %s\n", argv[i]);
                        return -1;
                    }
                }
                return 0;
            }
        } else if (strcmp(argv[1], "conntrack") == 0) {
            if (argc == 2 || strcmp(argv[2], "list") == 0) {
                opts->cmd = CMD_CONNTRACK_LIST;
                return 0;
            } else if (strcmp(argv[2], "flush") == 0) {
                opts->cmd = CMD_CONNTRACK_FLUSH;
                return 0;
            }
        } else if (strcmp(argv[1], "stats") == 0) {
            if (argc == 2 || strcmp(argv[2], "show") == 0) {
                opts->cmd = CMD_STATS_SHOW;
                if (argc > 3 && strcmp(argv[3], "--json") == 0) {
                    opts->json_output = 1;
                }
                return 0;
            } else if (strcmp(argv[2], "reset") == 0) {
                opts->cmd = CMD_STATS_RESET;
                return 0;
            }
        }
    }

    /* Daemon / monitor mode arguments */
    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"direction",  required_argument, 0, 'd'},
        {"mode",       required_argument, 0, 'm'},
        {"config",     required_argument, 0, 'c'},
        {"rules",      required_argument, 0, 'r'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:d:m:c:r:h", long_options, NULL)) != -1) {
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
        case 'r':
            opts->rules_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

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
