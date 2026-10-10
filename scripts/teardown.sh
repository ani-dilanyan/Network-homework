#!/usr/bin/env bash
# Removes the lab namespaces and stops any device daemons. Run as root.
pkill -f bin/secure_device 2>/dev/null || true
for ns in pc1 dev1 dev2 pc2; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
done
echo "Topology removed."
