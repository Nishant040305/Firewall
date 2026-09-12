#!/usr/bin/env python3
"""
High-Performance Stateful eBPF/XDP Firewall
===========================================
Combines all project documentation into a single PDF document using
pandoc and WeasyPrint with a professional academic stylesheet.
"""
import subprocess
import sys
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
CSS_FILE = os.path.join(SCRIPT_DIR, "print_style.css")

COMBINED_MD = os.path.join(DOCS_DIR, "COMBINED_DOCUMENTATION.md")
OUTPUT_HTML = os.path.join(PROJECT_ROOT, "Firewall_Documentation.html")
OUTPUT_PDF = os.path.join(PROJECT_ROOT, "Firewall_Documentation.pdf")

# Ordered list of documentation sections (without 00_INDEX.md)
DOC_ORDER = [
    ("README.md", os.path.join(PROJECT_ROOT, "README.md"), "Project Overview"),
    ("Design.md", os.path.join(PROJECT_ROOT, "Design.md"), "Architectural Blueprint"),
    ("01_CONTAINER_LAB_SETUP.md", os.path.join(DOCS_DIR, "01_CONTAINER_LAB_SETUP.md"), "Container Lab Environment"),
    ("02_EBPF_DATAPLANE.md", os.path.join(DOCS_DIR, "02_EBPF_DATAPLANE.md"), "eBPF/XDP Dataplane Architecture"),
    ("03_BUILD_PROCESS.md", os.path.join(DOCS_DIR, "03_BUILD_PROCESS.md"), "Build Process & Compilation"),
    ("04_USERSPACE_CONTROL_PLANE.md", os.path.join(DOCS_DIR, "04_USERSPACE_CONTROL_PLANE.md"), "Userspace Control Plane"),
    ("05_TESTING_AND_VALIDATION.md", os.path.join(DOCS_DIR, "05_TESTING_AND_VALIDATION.md"), "Testing & Benchmarking"),
    ("PACKET_PATH_VALIDATION.md", os.path.join(DOCS_DIR, "PACKET_PATH_VALIDATION.md"), "Packet Path Lifecycle"),
    ("ARCHITECTURE_AND_EXTENSIONS.md", os.path.join(DOCS_DIR, "ARCHITECTURE_AND_EXTENSIONS.md"), "Future Extensions"),
]


def combine_markdown():
    """Merge all markdown documents in order."""
    print("[*] Merging all markdown documents into single file...")
    chunks = []

    for filename, filepath, section_title in DOC_ORDER:
        if not os.path.exists(filepath):
            print(f"    [!] Skipping missing file: {filepath}")
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # Clean redundant markdown links pointing to local docs or directories
        def clean_link(match):
            text = match.group(1).strip("*` ")
            return f"**{text}**"

        # Remove dead/redundant links to .md files, docs/ directories, and anchors
        content = re.sub(r'\[([^\]]+)\]\((?:docs/)?(?:[0-9A-Za-z_]+\.md)?(?:\#[^\)]*)?\)', clean_link, content)
        content = re.sub(r'\[([^\]]+)\]\(docs/\)', clean_link, content)
        content = re.sub(r'\[([^\]]+)\]\([^)]+\.pdf\)', clean_link, content)

        chunks.append(f"\n\n<!-- SECTION START: {section_title} -->\n\n")
        chunks.append(content)
        chunks.append("\n\n")

    merged = "".join(chunks).strip()

    with open(COMBINED_MD, "w", encoding="utf-8") as f:
        f.write(merged)

    print(f"[+] Combined markdown generated: {COMBINED_MD} ({len(merged):,} characters)")
    return COMBINED_MD


def build_cover_page_html():
    """Returns HTML for an academic cover page (without author attribution)."""
    return """
<div class="cover-page">
    <div class="badge">Systems &amp; Network Security Project</div>
    <h1>High-Performance Stateful eBPF/XDP Firewall</h1>
    <div class="subtitle">Complete Technical Architecture, Implementation, and Evaluation Report</div>
    
    <div style="margin: 30px 0; font-size: 11pt; color: #93c5fd; max-width: 600px; line-height: 1.6;">
        A kernel-space stateful packet filtering system leveraging eBPF, XDP driver-layer hooks,
        TC egress classifiers, and an asynchronous userspace control plane with Incus container isolation.
    </div>

    <div class="metadata">
        <div>
            <p><strong>SYSTEM ARCHITECTURE</strong></p>
            <p style="color: #ffffff;">Stateful Packet Filtering</p>
            <p>XDP Ingress &bull; TC Egress</p>
        </div>
        <div>
            <p><strong>PLATFORM</strong></p>
            <p style="color: #ffffff;">Linux Kernel &ge; 5.15</p>
            <p>eBPF &bull; XDP &bull; TC &bull; libbpf</p>
        </div>
        <div>
            <p><strong>DATE</strong></p>
            <p style="color: #ffffff;">September 2026</p>
        </div>
    </div>
</div>
"""


def generate_pdf():
    """Converts combined markdown into PDF via pandoc + WeasyPrint."""
    combine_markdown()

    print("[*] Converting combined Markdown to standalone HTML via Pandoc...")
    pandoc_cmd = [
        "pandoc",
        COMBINED_MD,
        "-o", OUTPUT_HTML,
        "--standalone",
        "--self-contained",
        "--highlight-style=tango",
        "--metadata", "title=High-Performance Stateful eBPF/XDP Firewall",
        f"--css={CSS_FILE}",
    ]

    res = subprocess.run(pandoc_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[-] Pandoc failed: {res.stderr}")
        return False

    print(f"[+] HTML generated: {OUTPUT_HTML}")

    # Inject the cover page right after <body>
    with open(OUTPUT_HTML, "r", encoding="utf-8") as f:
        html_content = f.read()

    cover_html = build_cover_page_html()
    html_content = re.sub(r'(<body[^>]*>)', r'\1\n' + cover_html, html_content, count=1)

    # Write back HTML with cover page
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)

    print("[*] Rendering PDF with WeasyPrint...")
    try:
        import weasyprint
        doc = weasyprint.HTML(filename=OUTPUT_HTML)
        doc.write_pdf(OUTPUT_PDF)

        if os.path.exists(OUTPUT_PDF):
            size_kb = os.path.getsize(OUTPUT_PDF) / 1024.0
            print(f"[+] SUCCESS! Generated PDF: {OUTPUT_PDF} ({size_kb:.1f} KB)")
            return True
        else:
            print("[-] PDF file was not created.")
            return False
    except Exception as e:
        print(f"[-] WeasyPrint rendering error: {e}")
        return False


if __name__ == "__main__":
    success = generate_pdf()
    sys.exit(0 if success else 1)
