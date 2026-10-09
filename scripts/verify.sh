#!/usr/bin/env bash
# End-to-end check: DNS answer without BPF, REFUSED with BPF attached.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "re-executing with sudo..."
	exec sudo -E "$0" "$@"
fi

cleanup() {
	kill "${BPID:-}" "${SPID:-}" 2>/dev/null || true
	wait "${BPID:-}" "${SPID:-}" 2>/dev/null || true
	./scripts/netns.sh teardown >/dev/null 2>&1 || true
}
trap cleanup EXIT

make -s
./scripts/netns.sh teardown >/dev/null 2>&1 || true
./scripts/netns.sh setup

ip netns exec server dnsmasq --no-daemon --interface=veth-s \
	--listen-address=fd00:53::2 --address=/#/fd00:53::cafe \
	--no-resolv --no-hosts \
	>"/tmp/ebpf-dns-server.log" 2>&1 &
SPID=$!
for _ in $(seq 1 20); do
	if ! kill -0 "$SPID" 2>/dev/null; then
		echo "dnsmasq failed to start:"
		cat /tmp/ebpf-dns-server.log
		exit 1
	fi
	if grep -q 'started' /tmp/ebpf-dns-server.log 2>/dev/null; then
		break
	fi
	sleep 0.1
done
kill -0 "$SPID"

echo "=== dig WITHOUT bpf (expect NOERROR / fd00:53::cafe) ==="
out_without="$(ip netns exec client dig -6 @fd00:53::2 example.com AAAA +time=2 +tries=1)"
printf '%s\n' "$out_without"
grep -q 'status: NOERROR' <<<"$out_without"
grep -q 'fd00:53::cafe' <<<"$out_without"

ip netns exec client "$ROOT/dns_refused" -n client -o "$ROOT/dns_refused.bpf.o" \
	>"/tmp/ebpf-dns-loader.log" 2>&1 &
BPID=$!
sleep 1
if ! kill -0 "$BPID" 2>/dev/null; then
	echo "BPF loader failed:"
	cat /tmp/ebpf-dns-loader.log
	exit 1
fi

echo "=== dig WITH bpf (expect REFUSED) ==="
out_with="$(ip netns exec client dig -6 @fd00:53::2 example.com AAAA +time=2 +tries=1)"
printf '%s\n' "$out_with"
grep -q 'status: REFUSED' <<<"$out_with"

sleep 1.2
echo "=== loader stats line ==="
grep -E 'refused queries:|^netns' /tmp/ebpf-dns-loader.log || cat /tmp/ebpf-dns-loader.log

echo
echo "VERIFY OK"
