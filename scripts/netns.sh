#!/usr/bin/env bash
# Demo network: client netns <-> server netns over a veth pair (IPv6 only).
# eBPF attaches on client egress (veth-c); dnsmasq runs in server.
set -euo pipefail

CLIENT_NS="${CLIENT_NS:-client}"
SERVER_NS="${SERVER_NS:-server}"
CLIENT_IF="${CLIENT_IF:-veth-c}"
SERVER_IF="${SERVER_IF:-veth-s}"
CLIENT_IP="${CLIENT_IP:-fd00:53::1/64}"
SERVER_IP="${SERVER_IP:-fd00:53::2/64}"

ns_exists() {
	ip netns list | awk '{print $1}' | grep -qx "$1"
}

setup() {
	if ns_exists "$CLIENT_NS" && ns_exists "$SERVER_NS" \
		&& ip netns exec "$CLIENT_NS" ip link show "$CLIENT_IF" >/dev/null 2>&1 \
		&& ip netns exec "$SERVER_NS" ip link show "$SERVER_IF" >/dev/null 2>&1; then
		echo "netns $CLIENT_NS / $SERVER_NS already ready"
		return 0
	fi

	teardown >/dev/null 2>&1 || true

	ip netns add "$CLIENT_NS"
	ip netns add "$SERVER_NS"

	# Peer lives entirely inside the two namespaces — host routing untouched.
	ip link add "$CLIENT_IF" type veth peer name "$SERVER_IF"
	ip link set "$CLIENT_IF" netns "$CLIENT_NS"
	ip link set "$SERVER_IF" netns "$SERVER_NS"

	# nodad: skip Duplicate Address Detection so addresses are usable immediately.
	ip netns exec "$CLIENT_NS" bash -c "
		ip link set lo up
		ip link set $CLIENT_IF up
		ip -6 addr add $CLIENT_IP dev $CLIENT_IF nodad
	"
	ip netns exec "$SERVER_NS" bash -c "
		ip link set lo up
		ip link set $SERVER_IF up
		ip -6 addr add $SERVER_IP dev $SERVER_IF nodad
	"

	echo "client ($CLIENT_NS): $CLIENT_IF $CLIENT_IP"
	echo "server ($SERVER_NS): $SERVER_IF $SERVER_IP"
}

teardown() {
	ip netns delete "$CLIENT_NS" 2>/dev/null || true
	ip netns delete "$SERVER_NS" 2>/dev/null || true
	ip link delete "$CLIENT_IF" 2>/dev/null || true
	ip link delete "$SERVER_IF" 2>/dev/null || true
	echo "netns $CLIENT_NS / $SERVER_NS removed"
}

case "${1:-}" in
setup) setup ;;
teardown) teardown ;;
*)
	echo "Usage: $0 setup|teardown" >&2
	exit 1
	;;
esac
