//! The kernel and userspace path hashes must agree byte for byte.
//!
//! If they diverge, every allowlist lookup misses: nothing is ever filtered,
//! every known-good event still reaches userspace, and in phase 6 nothing would
//! ever be permitted. The failure looks like "the policy isn't working" rather
//! than like a bug, which is why this compares against the C directly instead
//! of asserting the Rust against hand-computed constants.

use quasar::policy::sync::{hash_bytes, path_hash};

// Compiled by build.rs from bpf/hash_host.c, which includes bpf/common.h --
// the same definition the probe compiles.
extern "C" {
    fn quasar_path_hash_host(path: *const u8, len: u32, out: *mut u8);
}

fn c_hash(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: the pointers are valid for the lengths passed, and the C writes
    // exactly QUASAR_HASH_LEN bytes into out.
    unsafe {
        quasar_path_hash_host(bytes.as_ptr(), bytes.len() as u32, out.as_mut_ptr());
    }
    out
}

#[test]
fn rust_and_c_agree_over_a_corpus() {
    let paths: Vec<Vec<u8>> = [
        "",
        "/",
        "/bin/sh",
        "/bin/sleep",
        "/usr/bin/wget",
        "/usr/bin/ssl_client",
        "/usr/local/bin/python3.12",
        "/usr/local/bin/gunicorn",
        "/proc/self/fd/6",
        "/proc/self/fd/7",
        // Neighbours that a truncating scheme would collide.
        "/usr/local/bin/pythona",
        "/usr/local/bin/pythonb",
        // Non-ASCII and an embedded space.
        "/opt/app/\u{00e9}t\u{00e9}",
        "/opt/my app/run",
    ]
    .iter()
    .map(|p| {
        let mut b = p.as_bytes().to_vec();
        b.push(0); // the probe hashes the NUL terminator too
        b
    })
    .collect();

    for bytes in &paths {
        assert_eq!(
            hash_bytes(bytes),
            c_hash(bytes),
            "hash disagreement on {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

#[test]
fn path_hash_includes_the_terminator() {
    // The probe hashes what bpf_probe_read_kernel_str returned, and that length
    // includes the NUL. Hashing the bare string instead would miss every time.
    let with_nul = c_hash(b"/bin/sh\0");
    let without = c_hash(b"/bin/sh");

    assert_eq!(path_hash("/bin/sh"), with_nul);
    assert_ne!(
        path_hash("/bin/sh"),
        without,
        "the terminator must be part of the hash"
    );
}

#[test]
fn distinct_paths_hash_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for path in [
        "/bin/sh",
        "/bin/sha",
        "/bin/hs",
        "/usr/bin/wget",
        "/usr/bin/wgot",
        "/a",
        "/b",
    ] {
        assert!(seen.insert(path_hash(path)), "collision on {path}");
    }
}

#[test]
fn long_paths_are_bounded_the_same_way() {
    // The probe hashes at most QUASAR_FILENAME_LEN bytes because that is the
    // size of its buffer; Rust has to stop at the same place.
    let long: Vec<u8> = std::iter::repeat_n(b'a', 600).collect();
    assert_eq!(hash_bytes(&long), c_hash(&long));
}
