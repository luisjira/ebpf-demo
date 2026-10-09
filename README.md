# eBPF DNS REFUSED demo

TC egress program that watches IPv6 UDP/53 leaving a NIC. Matching DNS **queries** are rewritten into DNS **responses** with `RCODE=REFUSED`, L2/L3/L4 addresses are swapped, and the packet is redirected to **ingress** of the same interface.

Two network namespaces keep the demo off the host stack:

| Netns    | Interface | Address       | Role                                      |
|----------|-----------|---------------|-------------------------------------------|
| `client` | `veth-c`  | `fd00:53::1`  | eBPF attach + `dig`                       |
| `server` | `veth-s`  | `fd00:53::2`  | dnsmasq                                   |

## How it works

1. Join netns `client`, then attach `dns_refused` as a **TC classifier on `veth-c` egress**.
2. Parse Ethernet → IPv6 → UDP; require dest port 53 and DNS QR=0 (query).
3. Set QR=1 and RCODE=5 (refused); fix the mandatory IPv6 UDP checksum; swap MAC/IPv6/ports.
4. `bpf_redirect(ifindex, BPF_F_INGRESS)` injects the packet as an inbound reply.

## Dependencies (Fedora)

```bash
sudo dnf install clang llvm make gcc libbpf-devel kernel-headers iproute bind-utils dnsmasq
```

Root is required (`CAP_SYS_ADMIN` to enter netns, `CAP_BPF` + `CAP_NET_ADMIN` to load/attach).

## Build

```bash
make
```

## Run

```bash
# Create the client/server namespaces and veth pair
sudo make setup
```

Then use three terminals:

```bash
# Terminal 1 — attach eBPF in the client netns
sudo ip netns exec client ./dns_refused

# Terminal 2 — start dnsmasq in the server netns
sudo ip netns exec server dnsmasq --no-daemon --interface=veth-s \
  --listen-address=fd00:53::2 --address=/#/fd00:53::cafe \
  --no-resolv --no-hosts

# Terminal 3 — query from the client netns
sudo ip netns exec client dig -6 @fd00:53::2 example.com AAAA
```

With the eBPF program attached, expect `status: REFUSED` and a rising counter in terminal 1. Stop the loader (Ctrl-C), run the `dig` command again, and dnsmasq should answer `fd00:53::cafe`.

```bash
sudo make teardown
```

## Further eBPF resources:
- [awesome-ebpf](https://github.com/qmonnet/awesome-ebpf)
- [Linux kernel tree sample programs](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/bpf)