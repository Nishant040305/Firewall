#!/usr/bin/env python3
"""Read network evidence without BPF privileges; filtering never changes enforcement."""
import argparse
from collections import Counter
import ipaddress
import json
import sys
import time


def matches(record, args):
    if record.get("type") != "network":
        return record.get("type") == "telemetry_health" and args.health
    if args.health:
        return False
    if args.ip and not any(
        ipaddress.ip_address(record[key]) in args.ip for key in ("src_ip", "dst_ip")
    ):
        return False
    return (
        (not args.direction or record.get("direction") == args.direction)
        and (not args.action or record.get("action") == args.action)
        and (args.port is None or args.port in (record.get("src_port"), record.get("dst_port")))
        and (not args.reason or record.get("reason") == args.reason)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", default=["telemetry/network.jsonl"])
    parser.add_argument("--ip", type=ipaddress.ip_network, help="IP or CIDR, either endpoint")
    parser.add_argument("--direction", choices=["in", "out"])
    parser.add_argument("--action", choices=["allow", "drop"])
    parser.add_argument("--port", type=int)
    parser.add_argument("--reason", choices=["state", "policy", "default_policy", "invalid_state", "malformed"])
    parser.add_argument("--health", action="store_true", help="only logging-health records")
    parser.add_argument("--follow", action="store_true", help="follow one file, including rotation")
    parser.add_argument("--summary", action="store_true", help="group by endpoints/service/verdict; omit ephemeral ports")
    parser.add_argument("--limit", type=int, default=20, help="maximum summary groups (default: 20)")
    args = parser.parse_args()
    if args.follow and len(args.files) != 1:
        parser.error("--follow requires one file")
    if args.port is not None and not 0 <= args.port <= 65535:
        parser.error("port must be 0..65535")
    if args.follow and args.summary:
        parser.error("--summary is offline only")
    if args.limit < 1:
        parser.error("--limit must be positive")
    if args.health and any((args.ip, args.direction, args.action, args.port is not None, args.reason, args.summary)):
        parser.error("--health cannot be combined with traffic filters or --summary")
    groups = Counter()

    def show(line):
        try:
            record = json.loads(line)
            if matches(record, args):
                if args.summary:
                    key = tuple(record.get(field) for field in
                                ("src_ip", "dst_ip", "dst_port", "protocol", "direction", "action", "reason"))
                    groups[key] += int(record.get("event_count", 1))
                else:
                    print(json.dumps(record, separators=(",", ":")), flush=True)
        except (ValueError, KeyError, TypeError):
            print("Skipping malformed network-log record", file=sys.stderr)

    for path in args.files:
        with open(path, encoding="utf-8") as stream:
            if not args.follow:
                for line in stream:
                    show(line)
                continue
            import os
            pending = ""
            try:
                while True:
                    chunk = stream.readline()
                    if chunk:
                        pending += chunk
                        if pending.endswith("\n"):
                            show(pending)
                            pending = ""
                        continue
                    time.sleep(0.25)
                    try:
                        stat = os.stat(path)
                    except FileNotFoundError:
                        continue
                    if stat.st_ino != os.fstat(stream.fileno()).st_ino:
                        replacement = open(path, encoding="utf-8")
                        stream.close()
                        stream = replacement
                        pending = ""
                    elif stat.st_size < stream.tell():
                        stream.seek(0)
                        pending = ""
            finally:
                stream.close()
    for key, count in groups.most_common(args.limit):
        record = dict(zip(("src_ip", "dst_ip", "dst_port", "protocol", "direction", "action", "reason"), key))
        record["event_count"] = count
        print(json.dumps(record, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyboardInterrupt) as error:
        if isinstance(error, OSError):
            print(str(error), file=sys.stderr)
            sys.exit(1)
