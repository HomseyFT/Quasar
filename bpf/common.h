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

#endif /* QUASAR_COMMON_H */
