#!/usr/bin/env bash
# Deletes the test containers and virtual networks.
set -euo pipefail

echo "[+] Stopping and deleting containers..."
for c in attacker client webserver admin; do
    incus delete -f "$c" 2>/dev/null || true
done

echo "[+] Deleting virtual networks..."
for net in incus-untrust incus-protect incus-mgmt incusbr-mgmt; do
    incus network delete "$net" 2>/dev/null || true
done

echo "[+] Cleanup complete."
