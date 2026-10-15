#!/usr/bin/env python3
"""Build/profile isolation regression suite; --kernel requires BPF privileges."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def make(*args, ok=True):
    result = subprocess.run(["make", "--no-print-directory", *args], cwd=ROOT,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if (result.returncode == 0) != ok:
        raise AssertionError(result.stdout)
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", action="store_true")
    args = parser.parse_args()
    count = 0
    for engine in ("stateful", "fastcache", "dualmap"):
        for timing, logging, obs in ((0, 0, "full"), (0, 0, "minimal"),
                                    (0, 0, "none"), (1, 0, "full"),
                                    (1, 0, "minimal"), (0, 1, "full"),
                                    (1, 1, "full")):
            flags = [f"ENGINE={engine}", f"TIMING={timing}", f"LOGGING={logging}",
                     f"OBSERVABILITY={obs}"]
            profile = ROOT / f"build/profiles/{engine}-t{timing}-l{logging}-{obs}"
            output = make(*flags, "-j4", "all", "test-ipv6")
            assert "warning:" not in output, output
            assert (profile / "firewall.bpf.o").is_file()
            assert (profile / "fw-ctl").is_file()
            assert (profile / "core/perf_mgr.o").exists() == bool(timing)
            assert (profile / "telemetry/network_log.o").exists() == bool(logging)
            assert (profile / "telemetry/console_bus.o").exists() == (not logging and obs == "full")
            # Optional artifacts from an explicit prior tools/baseline build
            # may exist; all must neither schedule nor rebuild them.
            plan = make(*flags, "-n", "all")
            assert "xdp_pass.bpf.c" not in plan
            assert "conntrack_bench_tool.c" not in plan
            assert not (profile / "firewall_fast.bpf.o").exists()
            assert not (profile / "firewall_zero_obs.bpf.o").exists()
            before = {p: p.stat().st_mtime_ns for p in profile.rglob("*.o")}
            make(*flags, "all")
            assert before == {p: p.stat().st_mtime_ns for p in before}
            symbols = subprocess.check_output(["nm", str(profile / "fw-ctl")], text=True)
            assert (" network_log_record" in symbols) == bool(logging)
            assert (" perf_mgr_show" in symbols) == bool(timing)
            deps = (profile / "firewall.bpf.d").read_text()
            assert ("engines/dualmap.bpf.h" in deps) == (engine == "dualmap")
            if args.kernel:
                output = make(*flags, "test-ipv6-kernel")
                assert "55 XDP/TC" in output, output
            count += 1
            print(f"PASS {profile.name}", flush=True)
    for invalid in (("ENGINE=typo",), ("TIMING=2",), ("LOGGING=2",),
                    ("TIMING=1", "OBSERVABILITY=none"),
                    ("LOGGING=1", "OBSERVABILITY=minimal")):
        make(*invalid, "all", ok=False)
    # A changed compiler flag invalidates the profile; a repeated invocation
    # with those same flags must be a no-op again.
    flags = ["ENGINE=fastcache", "TIMING=0", "LOGGING=0", "OBSERVABILITY=full"]
    obj = ROOT / "build/profiles/fastcache-t0-l0-full/core/cli.o"
    before = obj.stat().st_mtime_ns
    make(*flags, "CFLAGS=-O2 -g -Wall -Wextra -DFW_INCREMENTAL_TEST=1", "all")
    assert obj.stat().st_mtime_ns != before
    before = obj.stat().st_mtime_ns
    make(*flags, "CFLAGS=-O2 -g -Wall -Wextra -DFW_INCREMENTAL_TEST=1", "all")
    assert obj.stat().st_mtime_ns == before
    make(*flags, "all")  # Restore default flags.
    print(f"{count} profiles: build, isolation, incremental and feature-selection checks passed")


if __name__ == "__main__":
    main()
