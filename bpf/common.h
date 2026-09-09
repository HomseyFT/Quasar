/* Shared event layout.
 *
 * This header is the single source of truth for the bytes that cross the ring
 * buffer. The probes include it directly; build.rs runs bindgen over it to
 * generate the Rust mirror. Never hand-write the Rust side -- the drift it
 * would allow is silent and corrupts every event.
 *
 * The __VMLINUX_H__ guard lets the same header compile in two contexts: after
 * vmlinux.h for the BPF target, and standalone under bindgen on the host.
 */
#ifndef QUASAR_COMMON_H
#define QUASAR_COMMON_H

#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#define QUASAR_COMM_LEN     16
#define QUASAR_FILENAME_LEN 256
#define QUASAR_ADDR_LEN     16

/* Address families and protocols travel in the event rather than being looked
 * up per side, so the two languages cannot disagree about what a 2 means. */
#define QUASAR_AF_INET   2
#define QUASAR_AF_INET6  10
#define QUASAR_PROTO_TCP 6
#define QUASAR_PROTO_UDP 17

/* What happened to an exec. One event type covers all three so the log, the
 * counters and the screen do not need parallel shapes for the same fact. */
#define QUASAR_OUTCOME_OBSERVED    0  /* it ran, and nothing objected */
#define QUASAR_OUTCOME_WOULD_BLOCK 1  /* dry run: enforcement would have stopped it */
#define QUASAR_OUTCOME_BLOCKED     2  /* it was stopped (phase 6b) */

/* Arming, per cgroup. */
#define QUASAR_MODE_OFF     0
#define QUASAR_MODE_DRY_RUN 1
#define QUASAR_MODE_ENFORCE 2

/* Field order is chosen so the struct packs with no interior padding and no
 * tail padding: 8-byte scalars, then 4-byte scalars, then the arrays. */
struct exec_event {
	__u64 timestamp_ns;   /* bpf_ktime_get_ns, monotonic since boot */
	__u64 cgroup_id;      /* the cgroup dir's inode number */
	__u32 pid;            /* thread id */
	__u32 tgid;           /* what userspace calls the pid */
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u16 filename_len;   /* including the NUL; 0 if the read failed */
	__u8  outcome;        /* QUASAR_OUTCOME_* */
	__u8  _reserved;      /* named, so the struct still has no implicit hole */
	__u8  comm[QUASAR_COMM_LEN];
	__u8  filename[QUASAR_FILENAME_LEN];
};

/* An outbound connection attempt. Packs with no interior or tail padding:
 * 8-byte scalars, 4-byte scalars, then the arrays and the small trailer. */
struct connect_event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u8  comm[QUASAR_COMM_LEN];
	__u8  daddr[QUASAR_ADDR_LEN];   /* v4 occupies the first four bytes */
	__u16 dport;                    /* host byte order */
	__u8  family;                   /* QUASAR_AF_INET / QUASAR_AF_INET6 */
	__u8  protocol;                 /* QUASAR_PROTO_TCP / QUASAR_PROTO_UDP */
};

/* ---- allowlist map keys -------------------------------------------------
 *
 * Policy is pushed down into these maps, and a matching event dies in the
 * probe rather than crossing the ring buffer. The keys are shared with
 * userspace, so their layouts are pinned by the parity test alongside the
 * event structs.
 *
 * cgroup_id leads every key because policy is per container, and a container's
 * cgroup id changes each time it starts -- the maps are re-synced then.
 */

/* The path itself, not a digest of it.
 *
 * A hash only has to resist collisions while a collision means a missed
 * detection. Once enforcement exists a collision means an attacker chose a
 * file name that executes, so the class is removed rather than made difficult.
 * The cost is 240 bytes per entry, which is nothing on this box.
 *
 * A path that fills the buffer was truncated, and a truncated path is not an
 * identity. Both sides refuse those rather than storing a prefix that would
 * match some other binary.
 */
struct exec_key {
	__u64 cgroup_id;
	__u8  path[QUASAR_FILENAME_LEN];
};

/* LPM_TRIE keys.
 *
 * The kernel's key is a prefix length immediately followed by the data it
 * prefixes, and key_size counts both -- so the length is part of the struct and
 * the layout must have no padding anywhere. Byte arrays rather than a __u64
 * keep the alignment at 1 so nothing is inserted after prefixlen.
 *
 * The data is split out because it is addressed from two directions: the probe
 * builds the whole key, while userspace supplies only the data and lets the map
 * API prepend the length.
 *
 * The prefix always covers all 64 bits of cgroup_id, so the trie matches the
 * container exactly and then does longest-prefix matching on the address --
 * which is why 10.0.0.0/8 is one entry rather than sixteen million.
 */
#define QUASAR_CGROUP_PREFIX_BITS 64

struct cidr_data {
	__u8 cgroup_id[8];
	__u8 addr[4];               /* network order */
};

struct cidr_key {
	__u32 prefixlen;
	struct cidr_data data;
};

struct cidr_data6 {
	__u8 cgroup_id[8];
	__u8 addr[QUASAR_ADDR_LEN];
};

struct cidr_key6 {
	__u32 prefixlen;
	struct cidr_data6 data;
};

/* Arming state, per cgroup.
 *
 * The expiry is absolute and the probe compares it against bpf_ktime_get_ns
 * itself. Userspace renews it on a heartbeat, so a userspace that dies -- or
 * is killed -- cannot leave the kernel enforcing against nobody. The safe
 * state is reached by doing nothing, which is the only kind of safe state
 * worth having here.
 */
struct enforce_state {
	__u64 expires_at_ns;
	__u8  mode;            /* QUASAR_MODE_* */
	__u8  _reserved[7];
};

#endif /* QUASAR_COMMON_H */
