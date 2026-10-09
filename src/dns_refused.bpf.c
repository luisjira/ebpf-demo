// TC egress eBPF program: intercept outgoing DNS queries and bounce a
// DNS REFUSED response back to the local stack.
//
// Runs in netns "client" on veth-c (see scripts/netns.sh). IPv6 only.
// Live-demo flow (this hook runs for every packet leaving veth-c):
//   1. Parse Ethernet -> IPv6 -> UDP.
//   2. If destination port is 53 and the payload is a DNS *query*, rewrite
//      the packet in place into a DNS *response* with RCODE=REFUSED.
//   3. Swap L2/L3/L4 addresses so the packet looks like a reply from the
//      resolver we were talking to.
//   4. bpf_redirect(..., BPF_F_INGRESS) injects it as if it had just
//      arrived on this interface. The original query never goes out.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DNS_PORT 53
#define DNS_RCODE_REFUSED 5
#define DNS_QR_BIT 0x8000 /* query=0, response=1 */

/* RFC 1035 DNS header (12 bytes). Question section follows; we leave it. */
struct dnshdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

/* Slot 0: how many DNS queries we turned into REFUSED. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump_stats(void)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&stats, &key);

	if (val)
		__sync_fetch_and_add(val, 1);
}

/* Fold a 64-bit partial sum into an Internet checksum. */
static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	csum = (csum & 0xffffffff) + (csum >> 32);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

/*
 * IPv6 UDP checksum is mandatory (unlike IPv4). We only change DNS flags;
 * id+flags is 4 bytes so bpf_csum_diff size rules are satisfied. Swapping
 * IPv6 addresses / UDP ports does not change the checksum (sums commute).
 */
static __always_inline void update_udp_csum_for_flags(struct udphdr *udp,
						     struct dnshdr *dns,
						     __be16 new_flags)
{
	/* id|flags via memcpy — DNS is often 2-byte aligned after Ethernet. */
	__be32 old_word, new_word;
	__u16 old_csum = udp->check;
	__s64 diff;
	__u64 sum;

	__builtin_memcpy(&old_word, dns, sizeof(old_word));
	dns->flags = new_flags;
	__builtin_memcpy(&new_word, dns, sizeof(new_word));

	diff = bpf_csum_diff(&old_word, sizeof(old_word), &new_word,
			     sizeof(new_word), 0);
	sum = (__u64)((__u16)~old_csum) + diff;
	udp->check = csum_fold_helper(sum);
	/* RFC 768: checksum 0 is transmitted as 0xffff. */
	if (udp->check == 0)
		udp->check = 0xffff;
}

SEC("tc")
int dns_refused(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* --- L2: Ethernet --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK; /* IPv4 / ARP / ... : pass through */

	/* --- L3: IPv6 (fixed 40-byte header; ignore extension headers) --- */
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;
	if (ip6->nexthdr != IPPROTO_UDP)
		return TC_ACT_OK;

	/* --- L4: UDP --- */
	struct udphdr *udp = (void *)(ip6 + 1);
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;
	if (udp->dest != bpf_htons(DNS_PORT))
		return TC_ACT_OK; /* not a DNS query (we only match dest port 53) */

	/* --- DNS header --- */
	struct dnshdr *dns = (void *)(udp + 1);
	if ((void *)(dns + 1) > data_end)
		return TC_ACT_OK;

	__u16 flags = bpf_ntohs(dns->flags);
	if (flags & DNS_QR_BIT)
		return TC_ACT_OK; /* already a response; do not touch */

	/*
	 * Turn this query into a REFUSED response:
	 *   QR = 1  (this is now a response)
	 *   RCODE = 5 (REFUSED)  — lower 4 bits of the flags field
	 * Keep OPCODE and RD from the query so the client accepts the reply.
	 * Leave section counts alone so the UDP checksum only needs a flags fix.
	 */
	flags |= DNS_QR_BIT;
	flags = (flags & ~0x000F) | DNS_RCODE_REFUSED;
	update_udp_csum_for_flags(udp, dns, bpf_htons(flags));

	/* Swap MACs so the frame looks like it came from the peer. */
	unsigned char tmp_mac[ETH_ALEN];
	__builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	/* Swap IPv6 addresses (pseudo-header sum unchanged). */
	struct in6_addr tmp_ip6;
	__builtin_memcpy(&tmp_ip6, &ip6->saddr, sizeof(tmp_ip6));
	__builtin_memcpy(&ip6->saddr, &ip6->daddr, sizeof(tmp_ip6));
	__builtin_memcpy(&ip6->daddr, &tmp_ip6, sizeof(tmp_ip6));

	/* Swap UDP ports so dest is the original client port. */
	__be16 tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

	bump_stats();

	/* Hand the rewritten packet to ingress of the same NIC.
	 * Return value is the TC action (TC_ACT_REDIRECT on success). */
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
