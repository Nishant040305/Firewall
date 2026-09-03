# Container Lab Environment & Network Topology

## 1. Overview and Rationale

In the development and evaluation of a high-performance stateful eBPF/XDP firewall, establishing a realistic, isolated, and highly controllable network environment is paramount. This project employs **Incus** (a powerful, lightweight system container manager) to simulate a complex, multi-segment network topology residing entirely on a single Linux host.

### Why System Containers?

System containers (like Incus/LXD) are chosen over traditional full hardware virtualization (e.g., VirtualBox, VMware) or application containers (e.g., Docker) for several critical reasons:

- **Isolated Network Namespaces:** Each Incus container is allocated its own distinct network namespace, providing dedicated IP addresses, routing tables, and firewall rules independent of the host and other containers.
- **Low Overhead & High Density:** By sharing the host's kernel, system containers avoid the substantial CPU and memory overhead associated with hypervisors and full guest OS virtualization. This allows for running numerous nodes simultaneously without resource exhaustion.
- **Realistic Network Paths:** Traffic between containers passes through standard Linux networking primitives (veth pairs, bridge interfaces, and the host routing stack). This accurately replicates physical network hops, allowing the eBPF/XDP firewall to intercept packets at the realistic kernel ingress points (driver layer) on the host's forwarding path.
- **Full OS Environment:** Unlike Docker, which typically runs single applications, Incus provides a complete init system (systemd) and full operating system environment within the container, enabling the deployment of multifaceted attack scripts, diagnostic tools, and complete service stacks (e.g., Nginx).

---

## 2. Network Topology Diagram

The lab simulates a traditional DMZ/segmented enterprise network architecture. The host machine acts as the central router and firewall enforcement point, interconnecting three distinct security zones.

```text
                           +------------------------------------------------------+
                           |                     HOST MACHINE                     |
                           |                (Routing & Firewalling)               |
                           |                                                      |
                           |                eBPF/XDP FIREWALL HOOKS               |
                           +--+-----------------------+------------------------+--+
                              |                       |                        |
                   incus-untrust (Bridge)     incus-protect (Bridge)    incus-mgmt (Bridge)
                      10.10.1.1/24              10.10.2.1/24             10.10.99.1/24
                      Gateway                   Gateway                  Gateway
                        |   |                        |                        |
           veth_u1 <----+   +----> veth_u2           | veth_p1                | veth_m1
                |                    |               |                        |
 +--------------+---+    +-----------+------+   +----+-------------+   +------+-------------+
 |     Client       |    |     Attacker     |   |    Webserver     |   |      Admin         |
 |   (10.10.1.20)   |    |   (10.10.1.10)   |   |   (10.10.2.10)   |   |   (10.10.99.10)    |
 |                  |    |                  |   |                  |   |                    |
 | - curl, iperf3   |    | - hping3, nmap   |   | - Nginx, iperf3  |   | - SSH, tcpdump     |
 +------------------+    +------------------+   +------------------+   +--------------------+
 
 \__________________________/                   \__________________/   \____________________/
     Untrusted Segment                           Protected Segment      Management Segment
```

---

## 3. Container Node Specifications

The following table details the specific roles and configurations of each container within the lab ecosystem.

| Container Name | IP Address | Network Segment | Security Zone | Role / Purpose | Pre-installed Tools / Services |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`client`** | `10.10.1.20` | `incus-untrust` | Untrusted | Legitimate traffic source. Simulates normal user requests to the web server. | `curl`, `iperf3`, `tcpdump`, `iproute2` |
| **`attacker`** | `10.10.1.10` | `incus-untrust` | Untrusted | Hostile traffic generator. Simulates malicious actors executing SYN floods, port scans, and volumetric attacks. | `hping3`, `nmap`, `tcpdump`, `iputils-ping` |
| **`webserver`** | `10.10.2.10` | `incus-protect` | Protected / DMZ | Target application server. Hosts the services that the firewall is designed to protect. | `nginx` (port 80), `iperf3` (port 5201, server mode), `tcpdump` |
| **`admin`** | `10.10.99.10` | `incus-mgmt` | Management | Secure administrative workstation. Provides an out-of-band channel for monitoring and testing. | `curl`, `ping`, `tcpdump`, `iproute2` |

---

## 4. Network Segments and Security Zones

The topology is divided into three distinct L2 broadcast domains, implemented via Linux bridges on the host.

### A. Untrusted Segment (`incus-untrust`)
- **Subnet:** `10.10.1.0/24`
- **Host Gateway:** `10.10.1.1`
- **Purpose:** Represents the external internet or a hostile network environment. This zone houses the `client` and `attacker` nodes. All traffic originating from this zone must be treated with strict scrutiny by the host firewall.

### B. Protected Segment (`incus-protect`)
- **Subnet:** `10.10.2.0/24`
- **Host Gateway:** `10.10.2.1`
- **Purpose:** Represents the internal Data Center or DMZ. It houses the vulnerable `webserver`. The primary objective of the eBPF/XDP firewall is to selectively allow legitimate traffic from the untrusted zone while dropping malicious payloads before they consume host routing resources or reach this segment.

### C. Management Segment (`incus-mgmt`)
- **Subnet:** `10.10.99.0/24`
- **Host Gateway:** `10.10.99.1`
- **Purpose:** An isolated administration network. In firewall development, aggressive rules or kernel panics can easily sever connectivity. This dedicated segment prevents administrative lockout, ensuring the `admin` container maintains a reliable communication path to monitor the host and other segments, irrespective of the firewall rules applied to the data planes.

---

## 5. Host Routing and Inter-Container Communication

The host machine acts as a central router for the three container networks.

1. **Virtual Ethernet (veth) Pairs:** When an Incus container is launched, a `veth` pair is created. One end resides inside the container's isolated network namespace (appearing as `eth0`), and the other end is attached to the corresponding virtual bridge on the host (e.g., `incus-untrust`).
2. **IP Forwarding:** To allow traffic to flow between different subnets (e.g., from `10.10.1.0/24` to `10.10.2.0/24`), the host's Linux kernel must be configured to forward packets. This is enabled via the sysctl parameter: `net.ipv4.ip_forward = 1`.
3. **The Firewall Hook Point:** When the `attacker` sends a packet to the `webserver`, the packet travels from the container, across the `veth` pair, and hits the `incus-untrust` bridge on the host. The host's routing table determines the next hop is the `incus-protect` bridge. The eBPF/XDP firewall is attached directly to these host interfaces (or the forwarding path), allowing it to inspect, drop, or modify packets at the lowest possible level in the kernel network stack *before* standard routing overhead is incurred.

---

## 6. Lab Lifecycle Management

The environment is managed via automated shell scripts to ensure consistent and reproducible states.

### 6.1. Initialization (`scripts/setup_env.sh`)

The setup script performs the following ordered operations:

1. **Network Creation:** Instructs Incus to create the three bridge networks (`incus-untrust`, `incus-protect`, `incus-mgmt`).
2. **Temporary NAT Enabling:** Initially, Network Address Translation (NAT) is enabled on these bridges. This is crucial because the newly created containers require outbound internet access to download and install necessary packages (like `nginx`, `hping3`).
3. **Container Provisioning:** Launches the four containers using a base Linux image (e.g., Ubuntu/Alpine) and statically assigns their designated IP addresses on their respective networks.
4. **Software Installation:** Executes `apt-get` (or equivalent) inside each container via `incus exec` to install the specific tools required for their roles.
5. **The "NAT-then-Isolate" Strategy:** Once all software is installed, the script modifies the `incus-untrust` and `incus-protect` networks to **disable NAT**.
   - *Rationale:* Disabling NAT removes the host's iptables/nftables masquerading rules. This ensures that IP addresses remain un-translated, simulating a pure routed environment. All inter-segment traffic is forced directly through the host's raw IP forwarding path, which is precisely where the eBPF/XDP firewall is designed to operate and drop malicious packets.

### 6.2. Decommissioning (`scripts/teardown_env.sh`)

To return the host to a clean state and reclaim resources, the teardown script:
1. **Stops and Deletes Containers:** Issues commands to forcefully stop and permanently delete `client`, `attacker`, `webserver`, and `admin`.
2. **Removes Networks:** Deletes the `incus-untrust`, `incus-protect`, and `incus-mgmt` bridge interfaces and their associated configurations from the host system.
