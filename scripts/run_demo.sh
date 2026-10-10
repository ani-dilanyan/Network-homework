#!/usr/bin/env bash
# Full demo: topology -> handshake -> encrypted traffic -> capture -> verify.
# Run as root from the repository root after `make`:  sudo ./scripts/run_demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
PORT=8080
PSK="lab-secret"
LOGS="$ROOT/logs"
mkdir -p "$LOGS"

[ -x "$BIN/secure_device" ] || { echo "Build first: make"; exit 1; }

cleanup() { "$ROOT/scripts/teardown.sh" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$ROOT/scripts/setup_topology.sh" "$PORT"

echo "[1] Starting Device2 (responder) and Device1 (initiator)..."
ip netns exec dev2 "$BIN/secure_device" --role responder \
    --peer 10.0.12.1 --lan 10.0.2.0/24 --tcp-port "$PORT" --psk "$PSK" \
    > "$LOGS/dev2.log" 2>&1 &
sleep 0.5
ip netns exec dev1 "$BIN/secure_device" --role initiator \
    --peer 10.0.12.2 --lan 10.0.1.0/24 --tcp-port "$PORT" --psk "$PSK" \
    > "$LOGS/dev1.log" 2>&1 &

for _ in $(seq 1 50); do
    grep -q "session up" "$LOGS/dev1.log" 2>/dev/null && \
    grep -q "session up" "$LOGS/dev2.log" 2>/dev/null && break
    sleep 0.2
done
grep -h "handshake complete" "$LOGS"/dev*.log

echo "[2] Capturing on the Device1 <-> Device2 link..."
CAP_PID=""
if command -v tcpdump >/dev/null; then
    ip netns exec dev2 tcpdump -i wan0 -U -w "$LOGS/wan.pcap" "tcp port $PORT" \
        >/dev/null 2>&1 &
    CAP_PID=$!
    sleep 1
fi

echo "[3] Running echo test PC1 -> PC2 ..."
ip netns exec pc2 "$BIN/echo_test" server "$PORT" > "$LOGS/server.log" 2>&1 &
sleep 0.5
ip netns exec pc1 "$BIN/echo_test" client 10.0.2.2 "$PORT"

sleep 1
[ -n "$CAP_PID" ] && kill "$CAP_PID" 2>/dev/null || true
pkill -INT -f bin/secure_device || true
sleep 1.5

echo "[4] Device statistics:"
grep -h "final stats" "$LOGS"/dev*.log || true

if [ -n "$CAP_PID" ]; then
    echo "[5] Capture of the Device1<->Device2 link saved to logs/wan.pcap"
    echo "    Open it in Wireshark: IP/TCP headers are intact, payload is ciphertext."
fi
