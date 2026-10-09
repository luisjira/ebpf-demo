// Userspace loader: join the client netns, load the .o, attach TC egress,
// and print a live counter until Ctrl-C.
//
// All BPF load/attach happens after setns(), so the clsact qdisc lives on
// veth-c inside netns client — not on the host's real NIC.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop_requested;

static void on_signal(int sig)
{
	(void)sig;
	stop_requested = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level > LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, fmt, args);
}

#ifndef DEMO_NETNS
#define DEMO_NETNS "client"
#endif
#ifndef DEMO_IFACE
#define DEMO_IFACE "veth-c"
#endif

/* Switch this process into the demo network namespace before any BPF syscall. */
static int enter_netns(const char *name)
{
	char path[64];
	int fd, err;

	snprintf(path, sizeof(path), "/run/netns/%s", name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr,
			"netns '%s' not found (%s). Create it with: sudo make setup\n"
			"  (or: sudo ./scripts/netns.sh setup)\n",
			name, strerror(errno));
		return -1;
	}

	if (setns(fd, CLONE_NEWNET) < 0) {
		err = errno;
		fprintf(stderr, "setns(%s): %s\n", path, strerror(err));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"Usage: %s [-n NETNS] [-i IFACE] [-o OBJ]\n"
		"  -n NETNS   network namespace (default: %s); always entered before load\n"
		"  -i IFACE   egress interface inside the netns (default: %s)\n"
		"  -o OBJ     path to dns_refused.bpf.o (default: ./dns_refused.bpf.o)\n",
		argv0, DEMO_NETNS, DEMO_IFACE);
}

int main(int argc, char **argv)
{
	const char *obj_path = "dns_refused.bpf.o";
	const char *netns = DEMO_NETNS;
	char ifname[IF_NAMESIZE] = DEMO_IFACE;
	int ifindex = 0, err, opt, map_fd;
	bool created_hook = false;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_tc_hook hook;
	struct bpf_tc_opts attach_opts, detach_opts;

	while ((opt = getopt(argc, argv, "n:i:o:h")) != -1) {
		switch (opt) {
		case 'n':
			netns = optarg;
			break;
		case 'i':
			snprintf(ifname, sizeof(ifname), "%s", optarg);
			break;
		case 'o':
			obj_path = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	/* BPF load + TC attach must run in this netns (clsact is per-netns). */
	if (enter_netns(netns) < 0)
		return 1;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface '%s' in netns %s\n", ifname, netns);
		return 1;
	}

	libbpf_set_print(libbpf_print);

	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "failed to open %s: %s\n", obj_path, strerror(-err));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-err));
		goto cleanup_obj;
	}

	prog = bpf_object__find_program_by_name(obj, "dns_refused");
	if (!prog) {
		fprintf(stderr, "program 'dns_refused' not found in object\n");
		err = -ENOENT;
		goto cleanup_obj;
	}

	map = bpf_object__find_map_by_name(obj, "stats");
	if (!map) {
		fprintf(stderr, "map 'stats' not found in object\n");
		err = -ENOENT;
		goto cleanup_obj;
	}
	map_fd = bpf_map__fd(map);

	memset(&hook, 0, sizeof(hook));
	hook.sz = sizeof(hook);
	hook.ifindex = ifindex;
	hook.attach_point = BPF_TC_EGRESS;

	err = bpf_tc_hook_create(&hook);
	if (err == -EEXIST) {
		err = 0;
	} else if (err) {
		fprintf(stderr, "bpf_tc_hook_create: %s\n", strerror(-err));
		goto cleanup_obj;
	} else {
		created_hook = true;
	}

	memset(&attach_opts, 0, sizeof(attach_opts));
	attach_opts.sz = sizeof(attach_opts);
	attach_opts.prog_fd = bpf_program__fd(prog);

	err = bpf_tc_attach(&hook, &attach_opts);
	if (err) {
		fprintf(stderr, "bpf_tc_attach: %s\n", strerror(-err));
		goto cleanup_hook;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	printf("netns %s: DNS REFUSED hooked on %s (ifindex %d) egress.\n",
	       netns, ifname, ifindex);
	printf("Outgoing IPv6 UDP/53 queries in this netns are bounced as REFUSED.\n");
	printf("Ctrl-C to detach.\n\n");

	while (!stop_requested) {
		__u32 key = 0;
		__u64 count = 0;

		if (bpf_map_lookup_elem(map_fd, &key, &count) == 0)
			printf("\rrefused queries: %llu", (unsigned long long)count);
		fflush(stdout);
		sleep(1);
	}
	printf("\n");

	/* Detach needs the handle/priority that attach wrote back; prog_fd
	 * must be cleared (libbpf rejects a non-zero prog_fd on detach). */
	detach_opts = attach_opts;
	detach_opts.prog_fd = 0;
	detach_opts.prog_id = 0;
	detach_opts.flags = 0;
	err = bpf_tc_detach(&hook, &detach_opts);
	if (err)
		fprintf(stderr, "bpf_tc_detach: %s\n", strerror(-err));

cleanup_hook:
	if (created_hook) {
		/* Destroy the whole clsact qdisc, not only the egress filter. */
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		int destroy_err = bpf_tc_hook_destroy(&hook);
		if (destroy_err)
			fprintf(stderr, "bpf_tc_hook_destroy: %s\n", strerror(-destroy_err));
	}
cleanup_obj:
	bpf_object__close(obj);
	return err ? 1 : 0;
}
