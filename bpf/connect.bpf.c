#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Its own buffer, deliberately. pihole alone generates thousands of
 * udp_sendmsg calls per second, and a flood here must not be able to starve
 * the exec stream, which carries the primary signal. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

/* fentry runs before the kernel function body, so the destination is not on
 * the sock yet -- it has to come from the sockaddr argument. */
static __always_inline struct connect_event *reserve(__u8 family, __u8 protocol)
{
	struct task_struct *task;
	struct connect_event *e;
	__u64 id;

	e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
	if (!e)
		return NULL;

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
	 * would ship kernel stack to userspace. */
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->dport = 0;
	e->family = family;
	e->protocol = protocol;

	return e;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(quasar_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	struct connect_event *e;
	__u16 port = 0;
	__u32 addr = 0;

	BPF_CORE_READ_INTO(&addr, sin, sin_addr.s_addr);
	BPF_CORE_READ_INTO(&port, sin, sin_port);

	e = reserve(QUASAR_AF_INET, QUASAR_PROTO_TCP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, &addr, sizeof(addr));
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(quasar_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
	struct connect_event *e;
	__u16 port = 0;

	e = reserve(QUASAR_AF_INET6, QUASAR_PROTO_TCP);
	if (!e)
		return 0;

	BPF_CORE_READ_INTO(&e->daddr, sin6, sin6_addr.in6_u.u6_addr8);
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

	sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);
	if (sin) {
		BPF_CORE_READ_INTO(&addr, sin, sin_addr.s_addr);
		BPF_CORE_READ_INTO(&port, sin, sin_port);
	} else {
		/* A connected UDP socket carries no msg_name; the destination
		 * is the one the socket was connected to. */
		BPF_CORE_READ_INTO(&addr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&port, sk, __sk_common.skc_dport);
	}

	e = reserve(QUASAR_AF_INET, QUASAR_PROTO_UDP);
	if (!e)
		return 0;

	__builtin_memcpy(e->daddr, &addr, sizeof(addr));
	e->dport = bpf_ntohs(port);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
