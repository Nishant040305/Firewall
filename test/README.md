# Firewall Traffic Generation & Performance Test Suite

This directory contains traffic generation, attack simulation, and benchmark scripts using the **Client-Attacker-Webserver** model to evaluate firewall functionality and performance.

---

## 🏗️ Architecture & Roles

```text
       [ CLIENT (10.10.1.20) ]                   [ ATTACKER (10.10.1.10) ]
        Legitimate HTTP/iperf3                    SYN/UDP Flood, Port Scans
                  \                                   /
                   \                                 /
              [ incus-untrust (10.10.1.1/24) bridge ]
                                 │
                     ┌───────────────────────┐
                     │  FIREWALL (eBPF/TC)   │
                     │  - Ingress: XDP       │
                     │  - Egress:  TC Egress │
                     └───────────────────────┘
                                 │
              [ incus-protect (10.10.2.1/24) bridge ]
                                 │
                    [ WEBSERVER (10.10.2.10) ]
                     Nginx (Port 80), iperf3
```

---

## 🚀 Quick Start Guide

### 1. Start Services on the Webserver
```bash
# Starts Nginx on port 80 and iperf3 on port 5201
bash test/traffic_server.sh
```

### 2. Generate Legitimate Client Traffic
Simulates legitimate user requests and throughput benchmarks:
```bash
# Run all tests (Ping, HTTP GET, iperf3 benchmark)
bash test/traffic_client.sh 10.10.2.10 all

# Continuous HTTP request loop (observe firewall packet log live)
bash test/traffic_client.sh 10.10.2.10 loop

# Send 50 HTTP requests
bash test/traffic_client.sh 10.10.2.10 http 50
```

### 3. Generate Hostile Attacker Traffic
Simulates various attack vectors:
```bash
# Interactive menu to choose attack vector:
bash test/traffic_attacker.sh 10.10.2.10

# Direct attack triggers:
bash test/traffic_attacker.sh 10.10.2.10 syn 10    # 10-sec TCP SYN flood
bash test/traffic_attacker.sh 10.10.2.10 udp 10    # 10-sec UDP flood
bash test/traffic_attacker.sh 10.10.2.10 icmp 10   # 10-sec ICMP ping flood
bash test/traffic_attacker.sh 10.10.2.10 scan      # Nmap stealth port scan
bash test/traffic_attacker.sh 10.10.2.10 xmas 5    # Malformed TCP Xmas flags
bash test/traffic_attacker.sh 10.10.2.10 all       # Run all vectors sequentially
```

### 4. Run Automated End-to-End Performance Benchmark
Runs baseline testing, injects hostile traffic, and generates a comparison report:
```bash
bash test/benchmark_performance.sh 10.10.2.10
```

### 5. Multi-Threaded Python Traffic Generator
Custom concurrency and load testing tool:
```bash
# High-concurrency legitimate client traffic (100 req/sec)
python3 test/traffic_generator.py -H 10.10.2.10 -p 80 -c 20 -d 10 --role client

# High-rate UDP flood simulation
python3 test/traffic_generator.py -H 10.10.2.10 -p 53 -P udp -c 50 -d 5 --role attacker
```
