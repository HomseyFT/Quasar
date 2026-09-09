/* Exec observation, and the LSM hook that will enforce on it.
 *
 * Both programs live in one object because they share every map: the
 * allowlist, the arming state, the ring buffer. Separate objects would each
 * get their own copies of those, and sharing them would mean pinning into
 * bpffs -- a lifecycle to get wrong in exchange for nothing. They are still
 * attached independently, so a kernel without BPF LSM in its active list runs
 * the tracepoint perfectly well.
 */
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
 * and it is what the LSM hook consults before deciding to object. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct exec_key);
	__type(value, __u8);
	__uint(max_entries, 4096);
} exec_allow SEC(".maps");

/* Which cgroups are armed, and until when. Absent means off. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct enforce_state);
	__uint(max_entries, 512);
} enforce SEC(".maps");

/* The key is 264 bytes and the BPF stack is 512, so it is built in a per-cpu
 * slot rather than on the stack. One slot per program: the two never run
 * concurrently on a cpu, but a shared slot is a question nobody should have to
 * answer twice. */
#define SCRATCH_TRACEPOINT 0
#define SCRATCH_LSM        1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct exec_key);
	__uint(max_entries, 2);
} scratch SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *slot;

	slot = bpf_map_lookup_elem(&dropped, &key);
	if (slot)
		(*slot)++; /* per-cpu, so no atomic is needed */
}

/* The arming mode in force right now, which is off once the expiry passes.
 *
 * The probe checks the clock itself rather than trusting userspace to have
 * cleaned up. A userspace that dies cannot leave the kernel enforcing. */
static __always_inline __u8 mode_now(__u64 cgroup_id)
{
	struct enforce_state *state;

	state = bpf_map_lookup_elem(&enforce, &cgroup_id);
	if (!state)
		return QUASAR_MODE_OFF;
	if (state->expires_at_ns <= bpf_ktime_get_ns())
		return QUASAR_MODE_OFF;

	return state->mode;
}

/* Fill a scratch key from a NUL-terminated kernel string.
 *
 * Returns the length including the NUL, or 0 when the path could not be read
 * or did not fit. A path that filled the buffer was truncated, and a truncated
 * path is a prefix that could name a different binary -- so it is never
 * offered to the allowlist.
 */
static __always_inline int fill_key(struct exec_key *key, __u64 cgroup_id, const void *src)
{
	int len;

	__builtin_memset(key, 0, sizeof(*key));
	key->cgroup_id = cgroup_id;

	len = bpf_probe_read_kernel_str(key->path, QUASAR_FILENAME_LEN, src);
	if (len <= 0 || len >= QUASAR_FILENAME_LEN)
		return 0;

	return len;
}

static __always_inline int allowed(struct exec_key *key, int len)
{
	if (len == 0)
		return 0;

	return bpf_map_lookup_elem(&exec_allow, key) != NULL;
}

static __always_inline struct exec_event *emit(struct exec_key *key, int len, __u8 outcome)
{
	struct task_struct *task;
	struct exec_event *e;
	__u64 id;

	e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}

	e->timestamp_ns = bpf_ktime_get_ns();
	e->cgroup_id = key->cgroup_id;

	id = bpf_get_current_pid_tgid();
	e->tgid = id >> 32;
	e->pid = (__u32)id;

	id = bpf_get_current_uid_gid();
	e->gid = id >> 32;
	e->uid = (__u32)id;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* The scratch key was zeroed before the read, so this copies a fully
	 * initialised 256 bytes -- no tail of an earlier record ships out. */
	__builtin_memcpy(e->filename, key->path, sizeof(e->filename));
	e->filename_len = (__u16)len;
	e->outcome = outcome;
	e->_reserved = 0;

	return e;
}

SEC("tracepoint/sched/sched_process_exec")
int quasar_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 slot = SCRATCH_TRACEPOINT;
	unsigned int fname_off;
	struct exec_event *e;
	struct exec_key *key;
	__u64 cgroup_id;
	int len;

	key = bpf_map_lookup_elem(&scratch, &slot);
	if (!key)
		return 0;

	cgroup_id = bpf_get_current_cgroup_id();

	/* __data_loc packs the payload offset in its low 16 bits. */
	fname_off = ctx->__data_loc_filename & 0xffff;
	len = fill_key(key, cgroup_id, (char *)ctx + fname_off);

	/* Known good: userspace never sees it. */
	if (allowed(key, len))
		return 0;

	/* The LSM hook has already reported this one. Reporting it again would
	 * double every count and every alert -- and under enforcement this
	 * tracepoint never fires for such an exec at all, which is what makes
	 * the dry run predict what enforcement will do. */
	if (mode_now(cgroup_id) != QUASAR_MODE_OFF)
		return 0;

	e = emit(key, len, QUASAR_OUTCOME_OBSERVED);
	if (e)
		bpf_ringbuf_submit(e, 0);

	return 0;
}

/* Runs before the exec is committed, which is what makes refusing possible.
 *
 * This phase never refuses. The branch that returns -EPERM does not exist
 * here, so no bug in arming, expiry or the allowlist can stop a process from
 * running: the worst case is a log line. */
SEC("lsm/bprm_check_security")
int BPF_PROG(quasar_bprm_check, struct linux_binprm *bprm, int ret)
{
	__u32 slot = SCRATCH_LSM;
	struct exec_event *e;
	struct exec_key *key;
	__u64 cgroup_id;
	int len;

	/* Another LSM already refused. Never overturn a denial. */
	if (ret != 0)
		return ret;

	cgroup_id = bpf_get_current_cgroup_id();
	if (mode_now(cgroup_id) == QUASAR_MODE_OFF)
		return 0;

	key = bpf_map_lookup_elem(&scratch, &slot);
	if (!key)
		return 0;

	len = fill_key(key, cgroup_id, BPF_CORE_READ(bprm, filename));
	if (allowed(key, len))
		return 0;

	e = emit(key, len, QUASAR_OUTCOME_WOULD_BLOCK);
	if (e)
		bpf_ringbuf_submit(e, 0);

	return 0;
}
