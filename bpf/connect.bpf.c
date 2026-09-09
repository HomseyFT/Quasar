/* Egress probes.
 *
 * These record a connection *attempt*, not a completed connection. fentry runs
 * at function entry, before the handshake, so a refused or timed-out connection
 * produces an event exactly like a successful one does. That is the deliberate
 * choice: the exfiltration attempt that failed is the one worth alerting on,
 * and a monitor that only saw successes could be evaded by a peer that never
 * answers. It does mean "connections" in the policy model means "attempts", and
 * counts will exceed what netstat or a firewall log shows.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* What the kernel itself requires of the address argument. Matching it exactly
 * matters in both directions: stricter would silently miss real egress, looser
 * would report addresses the kernel is about to reject. */
#define SOCKADDR_IN_LEN  16 /* sizeof(struct sockaddr_in) */
#define SOCKADDR_IN6_MIN 24 /* SIN6_LEN_RFC2133 */

/* Its own buffer, deliberately. pihole alone generates thousands of
 * udp_sendmsg calls per second, and a flood here must not be able to starve
 * the exec stream, which carries the primary signal. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

/* Reservation failures are the buffer overflowing. Counting them in the kernel
 * is the only way userspace can know it happened -- a lost event is otherwise
 * indistinguishable from an event that never occurred, which would silently
 * corrupt anything phase 4 learns from observed behaviour. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} dropped SEC(".maps");

/* Longest-prefix matching in the kernel, so 10.0.0.0/8 is one entry rather
 * than sixteen million. This is what makes pihole affordable: its DNS traffic
 * matches an allowlist entry and dies here. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct cidr_key);
	__type(value, __u8);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} egress_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct cidr_key6);
	__type(value, __u8);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} egress_allow6 SEC(".maps");

/* A lookup asks for the full-length prefix; a stored /8 still matches, because
 * the trie compares only as many bits as the stored entry itself carries. */
static __always_inline int egress_allowed_v4(__u64 cgroup_id, const __u8 addr[4])
{
	struct cidr_key key;

	__builtin_memset(&key, 0, sizeof(key));
	key.prefixlen = QUASAR_CGROUP_PREFIX_BITS + 32;
	__builtin_memcpy(key.data.cgroup_id, &cgroup_id, sizeof(cgroup_id));
	__builtin_memcpy(key.data.addr, addr, sizeof(key.data.addr));

	return bpf_map_lookup_elem(&egress_allow, &key) != NULL;
}

static __always_inline int egress_allowed_v6(__u64 cgroup_id, const __u8 addr[QUASAR_ADDR_LEN])
{
	struct cidr_key6 key;

	__builtin_memset(&key, 0, sizeof(key));
	key.prefixlen = QUASAR_CGROUP_PREFIX_BITS + 128;
	__builtin_memcpy(key.data.cgroup_id, &cgroup_id, sizeof(cgroup_id));
	__builtin_memcpy(key.data.addr, addr, sizeof(key.data.addr));

	return bpf_map_lookup_elem(&egress_allow6, &key) != NULL;
}

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *slot;

	slot = bpf_map_lookup_elem(&dropped, &key);
	if (slot)
		(*slot)++; /* per-cpu, so no atomic is needed */
}

/* fentry runs before the kernel validates the address argument, so apply the
 * same checks it is about to. A message the kernel rejects never reaches the
 * wire, and reporting it would be a false positive scored as real egress. */
static __always_inline int addr_ok(void *addr, int len, __u16 want_family, int min_len)
{
	__u16 family = 0;

	if (!addr || len < min_len)
		return 0;
	/* sa_family_t is the first field of every sockaddr variant. */
	if (bpf_probe_read_kernel(&family, sizeof(family), addr) != 0)
		return 0;

	return family == want_family;
}

static __always_inline struct connect_event *reserve(__u8 family, __u8 protocol)
{
	struct task_struct *task;
	struct connect_event *e;
	__u64 id;

	e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}

	e->timestamp_ns = bpf_ktime_get_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;

	id = bpf_get_current_uid_gid();
	e->gid = id >> 32;
	e->uid = (__u32)id;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Every byte of the reservation is written: uninitialised bytes here
	 * would ship the tail of an earlier record to userspace. */
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->dport = 0;
	e->family = family;
	e->protocol = protocol;

	return e;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(quasar_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	struct connect_event *e;
	__u16 port = 0;
	__u32 addr = 0;

	if (!addr_ok(uaddr, addr_len, QUASAR_AF_INET, SOCKADDR_IN_LEN))
		return 0;

	BPF_CORE_READ_INTO(&addr, sin, sin_addr.s_addr);
	BPF_CORE_READ_INTO(&port, sin, sin_port);

	if (egress_allowed_v4(bpf_get_current_cgroup_id(), (const __u8 *)&addr))
		return 0;

	e = reserve(QUASAR_AF_INET, QUASAR_PROTO_TCP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, &addr, sizeof(addr));
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(quasar_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
	struct connect_event *e;
	__u8 addr[QUASAR_ADDR_LEN];
	__u16 port = 0;

	if (!addr_ok(uaddr, addr_len, QUASAR_AF_INET6, SOCKADDR_IN6_MIN))
		return 0;

	BPF_CORE_READ_INTO(&addr, sin6, sin6_addr.in6_u.u6_addr8);
	if (egress_allowed_v6(bpf_get_current_cgroup_id(), addr))
		return 0;

	e = reserve(QUASAR_AF_INET6, QUASAR_PROTO_TCP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, addr, sizeof(addr));
	BPF_CORE_READ_INTO(&port, sin6, sin6_port);
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(quasar_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	struct sockaddr_in *sin;
	struct connect_event *e;
	__u16 port = 0;
	__u32 addr = 0;
	int namelen;

	sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
	namelen = BPF_CORE_READ(msg, msg_namelen);

	if (sin) {
		if (!addr_ok(sin, namelen, QUASAR_AF_INET, SOCKADDR_IN_LEN))
			return 0;
		BPF_CORE_READ_INTO(&addr, sin, sin_addr.s_addr);
		BPF_CORE_READ_INTO(&port, sin, sin_port);
	} else {
		/* A connected UDP socket carries no msg_name; the destination
		 * is the one the socket was connected to. */
		BPF_CORE_READ_INTO(&addr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&port, sk, __sk_common.skc_dport);
	}

	if (egress_allowed_v4(bpf_get_current_cgroup_id(), (const __u8 *)&addr))
		return 0;

	e = reserve(QUASAR_AF_INET, QUASAR_PROTO_UDP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, &addr, sizeof(addr));
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* udp_sendmsg is the AF_INET path only; native v6 datagrams go here. */
SEC("fentry/udpv6_sendmsg")
int BPF_PROG(quasar_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	struct sockaddr_in6 *sin6;
	struct connect_event *e;
	__u8 addr[QUASAR_ADDR_LEN];
	__u16 port = 0;
	int namelen;

	sin6 = (struct sockaddr_in6 *)BPF_CORE_READ(msg, msg_name);
	namelen = BPF_CORE_READ(msg, msg_namelen);

	if (sin6 && !addr_ok(sin6, namelen, QUASAR_AF_INET6, SOCKADDR_IN6_MIN))
		return 0;

	if (sin6) {
		BPF_CORE_READ_INTO(&addr, sin6, sin6_addr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&port, sin6, sin6_port);
	} else {
		BPF_CORE_READ_INTO(&addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&port, sk, __sk_common.skc_dport);
	}

	if (egress_allowed_v6(bpf_get_current_cgroup_id(), addr))
		return 0;

	e = reserve(QUASAR_AF_INET6, QUASAR_PROTO_UDP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, addr, sizeof(addr));
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
