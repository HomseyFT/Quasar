//! `bpf/common.h` and the Rust structs describe the same bytes in two
//! languages, and a mismatch silently corrupts every event.
//!
//! Drift is prevented rather than detected: build.rs generates the Rust side
//! from the header, so the two cannot disagree. What these assertions pin is
//! the wire format itself, so that changing `common.h` is a deliberate act
//! with a visible consequence rather than an incidental one.

use std::mem::{align_of, offset_of, size_of};

use quasar::event::{
    cidr_data as CidrData, cidr_data6 as CidrData6, cidr_key as CidrKey, cidr_key6 as CidrKey6,
    exec_key as ExecKey, ConnectEvent, ExecEvent, QUASAR_ADDR_LEN, QUASAR_CGROUP_PREFIX_BITS,
    QUASAR_COMM_LEN, QUASAR_FILENAME_LEN, QUASAR_HASH_LEN,
};

#[test]
fn exec_event_layout_is_pinned() {
    assert_eq!(size_of::<ExecEvent>(), 312, "exec_event size");
    assert_eq!(align_of::<ExecEvent>(), 8, "exec_event alignment");

    assert_eq!(offset_of!(ExecEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(ExecEvent, cgroup_id), 8);
    assert_eq!(offset_of!(ExecEvent, pid), 16);
    assert_eq!(offset_of!(ExecEvent, tgid), 20);
    assert_eq!(offset_of!(ExecEvent, ppid), 24);
    assert_eq!(offset_of!(ExecEvent, uid), 28);
    assert_eq!(offset_of!(ExecEvent, gid), 32);
    assert_eq!(offset_of!(ExecEvent, filename_len), 36);
    assert_eq!(offset_of!(ExecEvent, comm), 40);
    assert_eq!(offset_of!(ExecEvent, filename), 56);
}

#[test]
fn exec_event_has_no_padding() {
    let fields = size_of::<u64>() * 2
        + size_of::<u32>() * 6
        + QUASAR_COMM_LEN as usize
        + QUASAR_FILENAME_LEN as usize;

    assert_eq!(
        size_of::<ExecEvent>(),
        fields,
        "exec_event grew padding; the probe writes every byte it reserves, so \
         padding ships uninitialised kernel stack to userspace"
    );
}

#[test]
fn array_lengths_match_the_header() {
    // Derived from the layout rather than from an instance, so the QUASAR_*
    // constants and the struct they size cannot drift apart.
    assert_eq!(
        offset_of!(ExecEvent, filename) - offset_of!(ExecEvent, comm),
        QUASAR_COMM_LEN as usize
    );
    assert_eq!(
        size_of::<ExecEvent>() - offset_of!(ExecEvent, filename),
        QUASAR_FILENAME_LEN as usize
    );
}

#[test]
fn connect_event_layout_is_pinned() {
    assert_eq!(size_of::<ConnectEvent>(), 72, "connect_event size");
    assert_eq!(align_of::<ConnectEvent>(), 8, "connect_event alignment");

    assert_eq!(offset_of!(ConnectEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(ConnectEvent, cgroup_id), 8);
    assert_eq!(offset_of!(ConnectEvent, pid), 16);
    assert_eq!(offset_of!(ConnectEvent, tgid), 20);
    assert_eq!(offset_of!(ConnectEvent, ppid), 24);
    assert_eq!(offset_of!(ConnectEvent, uid), 28);
    assert_eq!(offset_of!(ConnectEvent, gid), 32);
    assert_eq!(offset_of!(ConnectEvent, comm), 36);
    assert_eq!(offset_of!(ConnectEvent, daddr), 52);
    assert_eq!(offset_of!(ConnectEvent, dport), 68);
    assert_eq!(offset_of!(ConnectEvent, family), 70);
    assert_eq!(offset_of!(ConnectEvent, protocol), 71);
}

#[test]
fn connect_event_has_no_padding() {
    let fields = size_of::<u64>() * 2
        + size_of::<u32>() * 5
        + QUASAR_COMM_LEN as usize
        + QUASAR_ADDR_LEN as usize
        + size_of::<u16>()
        + size_of::<u8>() * 2;

    assert_eq!(
        size_of::<ConnectEvent>(),
        fields,
        "connect_event grew padding; the probe writes every byte it reserves, so \
         padding ships uninitialised kernel stack to userspace"
    );
}

// ---- allowlist map keys --------------------------------------------------
//
// A wrong size here is not a subtle bug: the kernel rejects an LPM_TRIE whose
// key_size does not count the prefix length, and a HASH lookup with a
// differently-shaped key silently never matches.

#[test]
fn exec_key_layout_is_pinned() {
    assert_eq!(size_of::<ExecKey>(), 24, "exec_key size");
    assert_eq!(align_of::<ExecKey>(), 8);
    assert_eq!(offset_of!(ExecKey, cgroup_id), 0);
    assert_eq!(offset_of!(ExecKey, path_hash), 8);
    assert_eq!(
        size_of::<ExecKey>(),
        size_of::<u64>() + QUASAR_HASH_LEN as usize,
        "exec_key must have no padding: it is compared byte for byte"
    );
}

#[test]
fn lpm_keys_count_the_prefix_length() {
    // The kernel's LPM key is a prefix length immediately followed by its data,
    // and key_size counts both. aya builds the same shape from the data type,
    // so these two must line up or the map is rejected at load.
    assert_eq!(size_of::<CidrKey>(), 4 + size_of::<CidrData>());
    assert_eq!(size_of::<CidrKey6>(), 4 + size_of::<CidrData6>());
}

#[test]
fn lpm_key_data_has_no_padding() {
    // Alignment 1 throughout, so nothing is inserted after prefixlen and the
    // compared bits are exactly cgroup id followed by address.
    assert_eq!(align_of::<CidrData>(), 1);
    assert_eq!(align_of::<CidrData6>(), 1);
    assert_eq!(size_of::<CidrData>(), 8 + 4);
    assert_eq!(size_of::<CidrData6>(), 8 + QUASAR_ADDR_LEN as usize);
    assert_eq!(offset_of!(CidrData, cgroup_id), 0);
    assert_eq!(offset_of!(CidrData, addr), 8);
    assert_eq!(offset_of!(CidrData6, addr), 8);
}

#[test]
fn the_cgroup_prefix_covers_the_whole_id() {
    // Every lookup matches the container exactly before matching the address.
    assert_eq!(QUASAR_CGROUP_PREFIX_BITS, u64::BITS);
}
