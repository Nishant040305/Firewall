#!/usr/bin/env python3
"""Dependency-free interactive build selector. Never starts the firewall."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def choose(title, options, default=0):
    print(f"\n{title}")
    for index, (_, label) in enumerate(options, 1):
        marker = " (default)" if index == default + 1 else ""
        print(f"  {index}. {label}{marker}")
    while True:
        answer = input(f"Choose [1-{len(options)}] [{default + 1}]: ").strip()
        if not answer:
            return options[default][0]
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        print("Please enter one of the listed numbers.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Select and preview only")
    args = parser.parse_args()
    print("Firewall build selector — compile only, no attachment.")
    print("Press Enter for defaults; Ctrl+C to cancel.")
    engine = choose("Engine", [("fastcache", "FastCache"),
                               ("stateful", "Stateful"), ("dualmap", "Dual map")])
    timing = choose("Performance timing", [("0", "Disabled"), ("1", "Enabled")])
    logging = choose("Network logging", [("0", "Disabled"), ("1", "Enabled")])
    if logging == "1":
        obs = "full"
        print("\nObservability: full (required by network logging).")
    else:
        options = [("full", "Full: counters and events"),
                   ("minimal", "Minimal: counters only")]
        if timing == "0":
            options.append(("none", "None: no monitoring"))
        else:
            print("\nTiming requires counters; 'none' is unavailable.")
        obs = choose("Observability", options)
    rate_limit = choose("SYN rate limiting (build-time)", [
        ("1", "Include limiter; configure runtime limits in config/firewall.yaml"),
        ("0", "Compile out limiter entirely: no checks, maps or counters"),
    ])
    print(f"Rate limiting: {'included (runtime configurable)' if rate_limit == '1' else 'compiled out (runtime settings ignored)' }.")
    anti_spoof = choose("Anti-spoofing (build-time)", [
        ("1", "Include source-prefix checks; disabled until configured"),
        ("0", "Compile out source-prefix checks entirely"),
    ])
    conn_limit = choose("TCP connection limit (build-time)", [
        ("1", "Include per-source concurrent connection cap"),
        ("0", "Compile out connection cap entirely"),
    ])
    default_jobs = os.cpu_count() or 1
    while True:
        answer = input(f"\nParallel build jobs [{default_jobs}]: ").strip()
        if not answer:
            jobs = default_jobs
            break
        if answer.isdigit() and int(answer) > 0:
            jobs = int(answer)
            break
        print("Please enter a positive integer.")
    command = ["make", f"-j{jobs}", "PRESET=default", f"ENGINE={engine}",
               f"TIMING={timing}", f"LOGGING={logging}", f"RATE_LIMIT={rate_limit}",
               f"ANTI_SPOOF={anti_spoof}", f"CONN_LIMIT={conn_limit}", f"OBSERVABILITY={obs}", "all"]
    print(f"\nCommand: {shlex.join(command)}")
    suffix = "-r0" if rate_limit == "0" else ""
    suffix += "-a0" if anti_spoof == "0" else ""
    suffix += "-c0" if conn_limit == "0" else ""
    print(f"Output: build/profiles/{engine}-t{timing}-l{logging}-{obs}{suffix}/")
    if args.dry_run:
        print("Preview only — nothing compiled or attached.")
        return 0
    if input("Build now? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Cancelled — nothing compiled or attached.")
        return 0
    # Do not inherit a parent make jobserver: the selected job count is explicit.
    env = dict(os.environ)
    env.pop("MAKEFLAGS", None)
    env.pop("MFLAGS", None)
    env.pop("MAKEOVERRIDES", None)
    return subprocess.run(command, cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        raise SystemExit(0)
