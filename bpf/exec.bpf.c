#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

/* Reservation failures are the buffer overflowing. Counting them in the kernel
 * is the only way userspace can know it happened -- a lost event is otherwise
 * indistinguishable from an event that never occurred. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} dropped SEC(".maps");

/* The allowlist, pushed down from userspace. A hit means the exec is known
 * good and userspace never sees it -- that is what keeps the volume tractable,
 * and it is the same machinery phase 6 turns into a return value change. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct exec_key);
	__type(value, __u8);
	__uint(max_entries, 16384);
} exec_allow SEC(".maps");

/* The filename must be read and hashed before deciding whether to reserve, and
 * 256 bytes is too much of the 512-byte BPF stack to spend. */
struct path_scratch {
	__u8 path[QUASAR_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct path_scratch);
	__uint(max_entries, 1);
} scratch SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *slot;

	slot = bpf_map_lookup_elem(&dropped, &key);
	if (slot)
		(*slot)++; /* per-cpu, so no atomic is needed */
}

SEC("tracepoint/sched/sched_process_exec")
int quasar_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct path_scratch *buf;
	struct task_struct *task;
	struct exec_event *e;
	struct exec_key key;
	unsigned int fname_off;
	__u32 zero = 0;
	__u64 cgroup_id;
	__u64 id;
	int len;

	buf = bpf_map_lookup_elem(&scratch, &zero);
	if (!buf)
		return 0;

	/* __data_loc packs the payload offset in its low 16 bits. */
	fname_off = ctx->__data_loc_filename & 0xffff;
	__builtin_memset(buf->path, 0, sizeof(buf->path));
	len = bpf_probe_read_kernel_str(buf->path, sizeof(buf->path),
					(char *)ctx + fname_off);

	cgroup_id = bpf_get_current_cgroup_id();

	/* Drop known-good execs here, before anything is reserved. */
	__builtin_memset(&key, 0, sizeof(key));
	key.cgroup_id = cgroup_id;
	quasar_path_hash(buf->path, len > 0 ? (__u32)len : 0, key.path_hash);
	if (bpf_map_lookup_elem(&exec_allow, &key))
		return 0;

	e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}

	e->timestamp_ns = bpf_ktime_get_ns();
	e->cgroup_id = cgroup_id;

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;

	id = bpf_get_current_uid_gid();
	e->gid = id >> 32;
	e->uid = (__u32)id;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* The scratch buffer was zeroed before the read, so this copies a fully
	 * initialised 256 bytes -- no tail of an earlier record ships out. */
	__builtin_memcpy(e->filename, buf->path, sizeof(e->filename));
	e->filename_len = len > 0 ? (__u32)len : 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
