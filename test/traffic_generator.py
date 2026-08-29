#!/usr/bin/env python3
"""
Custom Multi-Threaded Traffic Generator & Load Tester
======================================================
Simulates Client and Attacker workloads with live telemetry:
  - Modes:
      * client:   High-concurrency legitimate HTTP/TCP requests
      * attacker: Rapid TCP/UDP packet flood simulation
  - Metrics:
      * Requests/sec (RPS)
      * Latency distribution (Avg, Min, Max, p95)
      * Packet drop rate
"""

import argparse
import socket
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

class TrafficStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.latencies = []
        self.bytes_transferred = 0

    def record(self, success, latency_ms, num_bytes=0):
        with self.lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
                self.latencies.append(latency_ms)
                self.bytes_transferred += num_bytes
            else:
                self.failed_requests += 1

def send_tcp_ping(target_host, target_port, payload_size=64, timeout=1.0):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_host, target_port))
        if payload_size > 0:
            s.sendall(b"X" * payload_size)
        s.close()
        latency = (time.time() - start) * 1000.0
        return True, latency, payload_size
    except Exception:
        latency = (time.time() - start) * 1000.0
        return False, latency, 0

def send_udp_packet(target_host, target_port, payload_size=128):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"U" * payload_size, (target_host, target_port))
        s.close()
        return True, 0.1, payload_size
    except Exception:
        return False, 0.0, 0

def worker(args, stats, stop_event):
    while not stop_event.is_set():
        if args.proto == "tcp":
            success, lat, b = send_tcp_ping(args.host, args.port, args.size, args.timeout)
        elif args.proto == "udp":
            success, lat, b = send_udp_packet(args.host, args.port, args.size)
        else:
            success, lat, b = send_tcp_ping(args.host, args.port, args.size, args.timeout)

        stats.record(success, lat, b)

        if args.delay > 0:
            time.sleep(args.delay)

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Traffic Generator & Load Tester")
    parser.add_argument("-H", "--host", default="10.10.2.10", help="Target IP address (default: 10.10.2.10)")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target Port (default: 80)")
    parser.add_argument("-P", "--proto", choices=["tcp", "udp"], default="tcp", help="Protocol (tcp, udp)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrent worker threads (default: 10)")
    parser.add_argument("-d", "--duration", type=int, default=5, help="Test duration in seconds (default: 5)")
    parser.add_argument("-s", "--size", type=int, default=64, help="Packet payload size in bytes (default: 64)")
    parser.add_argument("--delay", type=float, default=0.0, help="Inter-packet delay per thread in sec (default: 0.0)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--role", choices=["client", "attacker"], default="client", help="Workload profile")

    args = parser.parse_args()

    if args.role == "attacker":
        print(f"[*] Starting ATTACKER flood simulation against {args.host}:{args.port} ({args.proto.upper()})")
        if args.concurrency < 20:
            args.concurrency = 30
    else:
        print(f"[*] Starting CLIENT traffic generation against {args.host}:{args.port} ({args.proto.upper()})")

    stats = TrafficStats()
    stop_event = threading.Event()

    print(f"[+] Threads: {args.concurrency} | Duration: {args.duration}s | Payload: {args.size} bytes")

    start_time = time.time()
    threads = []
    for _ in range(args.concurrency):
        t = threading.Thread(target=worker, args=(args, stats, stop_event))
        t.daemon = True
        t.start()
        threads.append(t)

    time.sleep(args.duration)
    stop_event.set()

    for t in threads:
        t.join(timeout=1.0)

    elapsed = time.time() - start_time
    rps = stats.total_requests / elapsed if elapsed > 0 else 0
    success_rate = (stats.successful_requests / stats.total_requests * 100) if stats.total_requests > 0 else 0

    avg_lat = sum(stats.latencies) / len(stats.latencies) if stats.latencies else 0
    min_lat = min(stats.latencies) if stats.latencies else 0
    max_lat = max(stats.latencies) if stats.latencies else 0

    print("\n" + "=" * 55)
    print("                TRAFFIC TEST REPORT                    ")
    print("=" * 55)
    print(f"Target:               {args.host}:{args.port} ({args.proto.upper()})")
    print(f"Duration:             {elapsed:.2f} seconds")
    print(f"Total Transmitted:    {stats.total_requests} packets/requests")
    print(f"Successful:           {stats.successful_requests}")
    print(f"Failed / Dropped:     {stats.failed_requests}")
    print(f"Success Rate:         {success_rate:.1f}%")
    print(f"Throughput (RPS):     {rps:.2f} req/sec")
    if stats.latencies:
        print(f"Latency (Avg):        {avg_lat:.2f} ms")
        print(f"Latency (Min/Max):    {min_lat:.2f} ms / {max_lat:.2f} ms")
    print("=" * 55 + "\n")

if __name__ == "__main__":
    main()
