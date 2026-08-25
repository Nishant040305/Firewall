#!/usr/bin/env bash
# Deletes the test containers and virtual networks.
set -euo pipefail

INCUS_CMD="incus"
if ! incus list >/dev/null 2>&1; then
    INCUS_CMD="sudo incus"
fi

echo "[+] Stopping and deleting containers..."
for c in attacker client webserver admin; do
    $INCUS_CMD delete -f "$c" 2>/dev/null || true
done

echo "[+] Deleting virtual networks..."
for net in incus-untrust incus-protect incus-mgmt incusbr-mgmt incusbr-untrusted incusbr-protected; do
    $INCUS_CMD network delete "$net" 2>/dev/null || true
done

echo "[+] Cleanup complete."
