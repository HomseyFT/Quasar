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
	struct task_struct *task;
	struct exec_event *e;
	unsigned int fname_off;
	__u64 id;
	int len;

	e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
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

	/* bpf_probe_read_kernel_str stops at the terminator and leaves the rest
	 * of the buffer untouched, and ring buffer memory is recycled -- so
	 * without this the tail of an earlier record ships to userspace. */
	__builtin_memset(e->filename, 0, sizeof(e->filename));

	/* __data_loc packs the payload offset in its low 16 bits. */
	fname_off = ctx->__data_loc_filename & 0xffff;
	len = bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
					(char *)ctx + fname_off);
	e->filename_len = len > 0 ? (__u32)len : 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
