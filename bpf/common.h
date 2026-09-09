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
	__u32 filename_len;   /* including the NUL; 0 if the read failed */
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

#define QUASAR_HASH_LEN 16

struct exec_key {
	__u64 cgroup_id;
	__u8  path_hash[QUASAR_HASH_LEN];
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

/* ---- the path hash ------------------------------------------------------
 *
 * The kernel and userspace must produce identical bytes or every lookup misses
 * and the filter silently becomes a no-op. This function is the one definition;
 * build.rs also compiles it for the host so a test can compare the two.
 *
 * Two FNV-1a passes with different offset bases give the 16 bytes SPEC.md
 * calls for without needing 128-bit arithmetic, which BPF does not have.
 *
 * FNV is not collision resistant. An attacker who chooses file names could
 * craft a path colliding with an allowed one; that only matters once phase 6
 * blocks on this, where a keyed hash would be the answer.
 */

#define QUASAR_FNV_PRIME   0x100000001b3ULL
#define QUASAR_FNV_OFFSET1 0xcbf29ce484222325ULL
#define QUASAR_FNV_OFFSET2 0x84222325cbf29ce4ULL

static inline void quasar_path_hash(const __u8 *path, __u32 len, __u8 out[QUASAR_HASH_LEN])
{
	__u64 h1 = QUASAR_FNV_OFFSET1;
	__u64 h2 = QUASAR_FNV_OFFSET2;
	__u32 i;

	if (len > QUASAR_FILENAME_LEN)
		len = QUASAR_FILENAME_LEN;

	for (i = 0; i < QUASAR_FILENAME_LEN; i++) {
		if (i >= len)
			break;
		h1 = (h1 ^ path[i]) * QUASAR_FNV_PRIME;
		h2 = (h2 ^ path[i]) * QUASAR_FNV_PRIME;
		h2 = (h2 << 1) | (h2 >> 63); /* decorrelate the two passes */
	}

	__builtin_memcpy(out, &h1, sizeof(h1));
	__builtin_memcpy(out + sizeof(h1), &h2, sizeof(h2));
}

#endif /* QUASAR_COMMON_H */
