//! The userspace mirror of `bpf/common.h`.
//!
//! The structs here are generated from that header at build time, so the two
//! sides cannot describe different bytes. See `bpf/common.h`.

use std::{borrow::Cow, mem::size_of};

mod sys {
    #![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

pub use sys::exec_event as ExecEvent;
pub use sys::{QUASAR_COMM_LEN, QUASAR_FILENAME_LEN};

impl ExecEvent {
    /// Decode one ring buffer record. Returns `None` if the record is too
    /// short to be one of these, which would mean the probe and the loader
    /// disagree about the format.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }
        // The ring buffer hands back borrowed, possibly unaligned bytes.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
    }

    pub fn comm(&self) -> Cow<'_, str> {
        nul_terminated(&self.comm)
    }

    pub fn filename(&self) -> Cow<'_, str> {
        nul_terminated(&self.filename)
    }
}

fn nul_terminated(bytes: &[u8]) -> Cow<'_, str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}
