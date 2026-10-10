#!/usr/bin/env bash
# Builds the lab topology with Linux network namespaces:
#
#   pc1 ---- dev1 ==== dev2 ---- pc2
#   10.0.1.2  10.0.1.1 | 10.0.12.1  10.0.12.2 | 10.0.2.1  10.0.2.2
#
# and installs the iptables rules that send selected TCP traffic on the
# devices to NFQUEUE. Run as root.  Usage: sudo ./setup_topology.sh [PORT]
set -euo pipefail

PORT="${1:-8080}"
QUEUE=0

for ns in pc1 dev1 dev2 pc2; do
    ip netns del "$ns" 2>/dev/null || true
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

link() {  # link <nsA> <ifA> <nsB> <ifB>
    ip link add "tmpA" type veth peer name "tmpB"
    ip link set tmpA netns "$1"; ip -n "$1" link set tmpA name "$2"
    ip link set tmpB netns "$3"; ip -n "$3" link set tmpB name "$4"
}

link pc1  eth0 dev1 lan0
link dev1 wan0 dev2 wan0
link dev2 lan0 pc2  eth0

ip -n pc1  addr add 10.0.1.2/24  dev eth0
ip -n dev1 addr add 10.0.1.1/24  dev lan0
ip -n dev1 addr add 10.0.12.1/24 dev wan0
ip -n dev2 addr add 10.0.12.2/24 dev wan0
ip -n dev2 addr add 10.0.2.1/24  dev lan0
ip -n pc2  addr add 10.0.2.2/24  dev eth0

for pair in "pc1 eth0" "dev1 lan0" "dev1 wan0" "dev2 wan0" "dev2 lan0" "pc2 eth0"; do
    set -- $pair
    ip -n "$1" link set "$2" up
    # Disable offloads so NFQUEUE sees real, MTU-sized packets with real checksums
    if command -v ethtool >/dev/null; then
        ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    fi
done

ip -n pc1  route add default via 10.0.1.1
ip -n pc2  route add default via 10.0.2.1
ip -n dev1 route add 10.0.2.0/24 via 10.0.12.2
ip -n dev2 route add 10.0.1.0/24 via 10.0.12.1

for d in dev1 dev2; do
    ip netns exec "$d" sysctl -qw net.ipv4.ip_forward=1
    # Encrypted segments are 24 bytes longer than the original; tell conntrack
    # (if loaded) not to mark them out-of-window.
    ip netns exec "$d" sysctl -qw net.netfilter.nf_conntrack_tcp_be_liberal=1 2>/dev/null || true

    # Leave room for the 24-byte tag+counter so packets never exceed the MTU.
    ip netns exec "$d" iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss 1400

    # Send selected traffic to the userspace device daemon. No --queue-bypass:
    # if the daemon is not running, protected traffic is dropped (fail closed).
    ip netns exec "$d" iptables -A FORWARD -p tcp --dport "$PORT" -j NFQUEUE --queue-num "$QUEUE"
    ip netns exec "$d" iptables -A FORWARD -p tcp --sport "$PORT" -j NFQUEUE --queue-num "$QUEUE"
done

echo "Topology ready. Protected TCP port: $PORT"
