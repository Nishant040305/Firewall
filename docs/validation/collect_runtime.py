#!/usr/bin/env python3
"""Read-only local attachment inventory; preserves errors, exits and timestamps.

No traffic generation, attachment, flushing, service restart or tuning. Run from
the repository root. Privileged reads use sudo -n, never a password prompt.
"""
import datetime
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/validation/evidence/runtime"
OUT.mkdir(parents=True, exist_ok=True)
records = []


def capture(name, argv):
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=45)
        record = dict(name=name, argv=argv, started_at=start,
                      exit_code=result.returncode, stdout=result.stdout,
                      stderr=result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        record = dict(name=name, argv=argv, started_at=start, exit_code=None,
                      stdout="", stderr=str(exc))
    (OUT / (name + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    records.append(record)
    return record


capture("date", ["date", "-Iseconds"])
capture("identity", ["id"])
capture("kernel", ["uname", "-a"])
capture("revision", ["git", "rev-parse", "HEAD"])
capture("status", ["git", "status", "--short"])
capture("cpu", ["lscpu"])
capture("ip_link", ["ip", "link", "show"])
capture("ip_d_link", ["ip", "-d", "link", "show"])
capture("ip_address", ["ip", "-br", "address"])
capture("routes", ["ip", "route", "show", "table", "all"])
capture("rules", ["ip", "rule", "show"])
capture("forwarding", ["sysctl", "net.ipv4.ip_forward"])
capture("bridge_link", ["bridge", "link", "show"])
capture("processes", ["ps", "-eo", "pid,args"])
sudo = [] if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0 else ["sudo", "-n"]
bpf = shutil.which("bpftool")
if not bpf:
    candidates = sorted(pathlib.Path("/usr/lib/linux-tools").glob("**/bpftool"))
    bpf = str(candidates[-1]) if candidates else "bpftool"
capture("bpftool_version", [bpf, "version"])
capture("bpftool_net", sudo + [bpf, "net", "show"])
capture("bpftool_prog", sudo + [bpf, "prog", "show"])
capture("bpftool_maps", sudo + [bpf, "map", "show"])
capture("nft_ruleset", sudo + ["nft", "list", "ruleset"])
incus = capture("incus_list", ["incus", "list", "--format", "json"])
prefix = []
if incus["exit_code"] != 0:
    incus = capture("incus_list_privileged", sudo + ["incus", "list", "--format", "json"])
    prefix = sudo
if incus["exit_code"] == 0:
    for container in ("client", "attacker", "webserver", "admin"):
        capture(container + "_veth", prefix + ["incus", "config", "get", container, "volatile.eth0.host_name"])
        capture(container + "_config", prefix + ["incus", "config", "show", container, "--expanded"])
        for key, args in (("link", ["ip", "-d", "link"]), ("addr", ["ip", "address"]),
                          ("route", ["ip", "route"]), ("offloads", ["ethtool", "-k", "eth0"])):
            capture(container + "_" + key, prefix + ["incus", "exec", container, "--"] + args)
links = capture("ip_links_json", ["ip", "-j", "link", "show"])
try:
    interfaces = [row["ifname"] for row in json.loads(links["stdout"])]
except (ValueError, KeyError):
    interfaces = []
for iface in interfaces:
    safe = iface.replace("/", "_")
    for key, args in (("qdisc", ["tc", "-s", "qdisc", "show", "dev", iface]),
                      ("ingress", ["tc", "-s", "filter", "show", "dev", iface, "ingress"]),
                      ("egress", ["tc", "-s", "filter", "show", "dev", iface, "egress"]),
                      ("offloads", ["ethtool", "-k", iface])):
        capture(safe + "_" + key, args)
# The original utility uses sudo internally. A noninteractive outer sudo both
# avoids prompting and makes its internal reads run as root if access exists.
capture("trace_packet_path", sudo + ["bash", "scripts/trace_packet_path.sh"])
capture("trace_packet_path_unprivileged", ["bash", "scripts/trace_packet_path.sh"])
(OUT / "inventory.json").write_text(json.dumps(records, indent=2) + "\n")
print(f"Preserved {len(records)} command records in {OUT}")
