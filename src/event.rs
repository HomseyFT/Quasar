//! The userspace mirror of `bpf/common.h`.
//!
//! The structs here are generated from that header at build time, so the two
//! sides cannot describe different bytes. See `bpf/common.h`.

use std::{
    borrow::Cow,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

mod sys {
    #![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

pub use sys::connect_event as ConnectEvent;
pub use sys::exec_event as ExecEvent;
pub use sys::{cidr_data, cidr_data6, cidr_key, cidr_key6, exec_key};
pub use sys::{
    QUASAR_ADDR_LEN, QUASAR_AF_INET, QUASAR_AF_INET6, QUASAR_CGROUP_PREFIX_BITS, QUASAR_COMM_LEN,
    QUASAR_FILENAME_LEN, QUASAR_HASH_LEN, QUASAR_PROTO_TCP, QUASAR_PROTO_UDP,
};

/// Decode one ring buffer record. Returns `None` if the record is too short to
/// be the expected type, which would mean the probe and the loader disagree
/// about the format.
fn from_bytes<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // The ring buffer hands back borrowed, possibly unaligned bytes.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}

impl ExecEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_bytes(bytes)
    }

    pub fn comm(&self) -> Cow<'_, str> {
        nul_terminated(&self.comm)
    }

    pub fn filename(&self) -> Cow<'_, str> {
        nul_terminated(&self.filename)
    }
}

impl ConnectEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        from_bytes(bytes)
    }

    pub fn comm(&self) -> Cow<'_, str> {
        nul_terminated(&self.comm)
    }

    pub fn destination(&self) -> IpAddr {
        if u32::from(self.family) == QUASAR_AF_INET6 {
            IpAddr::V6(Ipv6Addr::from(self.daddr))
        } else {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&self.daddr[..4]);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match u32::from(self.protocol) {
            QUASAR_PROTO_TCP => "tcp",
            QUASAR_PROTO_UDP => "udp",
            _ => "?",
        }
    }
}

/// One event off either ring buffer. The probes deliver on separate buffers so
/// a flood of one cannot starve the other, and both stamp `bpf_ktime_get_ns`,
/// so userspace can still order them against each other.
///
/// The exec variant is boxed: its 256-byte filename would otherwise set the
/// size of every queue slot, including the connect events that are the bulk of
/// the traffic. Process launches are rare enough to afford the allocation.
#[derive(Clone, Debug)]
pub enum Event {
    Exec(Box<ExecEvent>),
    Connect(ConnectEvent),
}

impl Event {
    pub fn cgroup_id(&self) -> u64 {
        match self {
            Self::Exec(e) => e.cgroup_id,
            Self::Connect(e) => e.cgroup_id,
        }
    }

    pub fn pid(&self) -> u32 {
        match self {
            Self::Exec(e) => e.pid,
            Self::Connect(e) => e.pid,
        }
    }

    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Exec(e) => e.timestamp_ns,
            Self::Connect(e) => e.timestamp_ns,
        }
    }
}

fn nul_terminated(bytes: &[u8]) -> Cow<'_, str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}
