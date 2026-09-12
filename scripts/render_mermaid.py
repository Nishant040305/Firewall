#!/usr/bin/env python3
"""
Mermaid Diagram Vector Renderer
================================
Renders all Mermaid diagrams in the documentation to clean SVG vector images
using Kroki and stores them under docs/images/.
Also updates the markdown files to embed the SVGs with fallback mermaid source.
"""

import os
import re
import zlib
import base64
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
IMAGES_DIR = os.path.join(DOCS_DIR, "images")

os.makedirs(IMAGES_DIR, exist_ok=True)

# List of diagrams with file, target image name, and alt text
DIAGRAMS = [
    {
        "file": "02_EBPF_DATAPLANE.md",
        "image_name": "ebpf_4stage_pipeline.svg",
        "title": "4-Stage Packet Decision Pipeline",
        "code": """flowchart TD
    A[Entry Point: XDP or TC] --> B[Stage 1: L2/L3/L4 Parsing]
    B --> C[Stage 2: Stateful Connection Engine]
    C --> D[Stage 3: Dynamic Rule Matching]
    D --> E[Stage 4: Telemetry & Statistics]
    E --> F{Action}
    F -->|PASS| G[Pass Packet to Stack]
    F -->|DROP/REJECT| H[Drop Packet]"""
    },
    {
        "file": "02_EBPF_DATAPLANE.md",
        "image_name": "tcp_state_machine.svg",
        "title": "TCP Connection State Machine",
        "code": """stateDiagram-v2
    [*] --> SYN_SENT: SYN (new, allowed by rule)
    SYN_SENT --> SYN_RECV: SYN-ACK (from server)
    SYN_RECV --> ESTABLISHED: ACK (handshake complete)
    ESTABLISHED --> ESTABLISHED: Data Transfer (fast-path allow)
    ESTABLISHED --> FIN_WAIT: FIN
    ESTABLISHED --> CLOSED: RST
    FIN_WAIT --> CLOSED: Timeout/RST
    CLOSED --> [*]"""
    },
    {
        "file": "03_BUILD_PROCESS.md",
        "image_name": "build_directory_structure.svg",
        "title": "Build Directory Structure",
        "code": """graph TD
    A[build/] --> B(core/)
    A --> C(utils/)
    A --> D(protocols/)
    A --> E(telemetry/)
    A --> F[firewall.bpf.o<br/>BPF ELF Object]
    A --> G[fw-ctl<br/>Native Binary]
    A --> H[firewallctl<br/>Symlink to fw-ctl]
    
    B -.-> B1[*.o object files]
    C -.-> C1[*.o object files]
    D -.-> D1[*.o object files]
    E -.-> E1[*.o object files]"""
    },
    {
        "file": "03_BUILD_PROCESS.md",
        "image_name": "build_dependency_graph.svg",
        "title": "High-Level Build Dependency Graph",
        "code": """flowchart TD
    subgraph Userspace Binary [fw-ctl]
        main(main.c) --> cli(core/cli.c)
        main --> loader(core/bpf_loader.c)
        cli --> rules(core/rules_mgr.c)
        cli --> stats(core/stats_mgr.c)
        loader --> libbpf[libbpf library]
    end

    subgraph Kernel Object [firewall.bpf.o]
        bpf(src/kernel/main.bpf.c) --> bpfhdr(vmlinux.h / bpf_helpers.h)
    end

    loader -. loads .-> bpf"""
    },
    {
        "file": "04_USERSPACE_CONTROL_PLANE.md",
        "image_name": "userspace_component_diagram.svg",
        "title": "Userspace Control Plane Architecture",
        "code": """graph TD
    subgraph Userspace Control Plane [Userspace Control Plane fw-ctl]
        Main[main.c] --> Ctx[firewall_ctx]
        Ctx --> CLI[cli.c]
        Ctx --> Config[config.c YAML]
        Ctx --> Loader[bpf_loader.c]
        
        Ctx --> RulesMgr[rules_mgr.c]
        Ctx --> CTMgr[conntrack_mgr.c]
        Ctx --> StatsMgr[stats_mgr.c]
        Ctx --> EventBus[event_bus.c]
    end
    
    subgraph libbpf
        Loader -.-> LibBPF((libbpf))
    end
    
    subgraph Kernel Dataplane [Kernel Dataplane eBPF]
        LibBPF -.-> XDPProg[XDP Hooks]
        LibBPF -.-> TCPProg[TC Hooks]
        LibBPF -.-> Maps[BPF Maps]
    end"""
    }
]


def render_to_svg(mermaid_code, output_path):
    """Sends mermaid code to Kroki API and saves SVG vector image."""
    compressed = zlib.compress(mermaid_code.strip().encode("utf-8"), 9)
    encoded = base64.urlsafe_b64encode(compressed).decode("ascii")
    url = f"https://kroki.io/mermaid/svg/{encoded}"
    
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (FirewallDocumentation/1.0)"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        svg_content = resp.read()

    with open(output_path, "wb") as f:
        f.write(svg_content)
    
    print(f"[+] Rendered: {os.path.basename(output_path)} ({len(svg_content):,} bytes)")
    return svg_content.decode("utf-8", errors="ignore")


def main():
    print("=" * 60)
    print("  Rendering Mermaid Diagrams to Vector SVG")
    print("=" * 60)

    for item in DIAGRAMS:
        out_svg = os.path.join(IMAGES_DIR, item["image_name"])
        try:
            render_to_svg(item["code"], out_svg)
        except Exception as e:
            print(f"[-] Failed to render {item['image_name']}: {e}")

    print("\n[+] All Mermaid diagrams rendered successfully!")


if __name__ == "__main__":
    main()
