//! Push the allowlist down into the BPF maps.
//!
//! Userspace never sees a known-good event: the policy lives in kernel maps and
//! matching events die in the probe. This module is the userspace half of that,
//! and it is also exactly the machinery phase 6 needs -- enforcement becomes a
//! return value change rather than new infrastructure.
//!
//! Keys are per cgroup id, and a container's cgroup id changes every time it
//! starts, so a container's entries are rewritten under its new id on each
//! start rather than being written once at boot.

use anyhow::{Context, Result};
use aya::{
    maps::{lpm_trie::Key, HashMap, LpmTrie, MapData},
    Ebpf, Pod,
};
use ipnet::IpNet;

use super::{EgressRule, ExecRule, Policy, Source};
use crate::event::{
    cidr_data, cidr_data6, exec_key, QUASAR_CGROUP_PREFIX_BITS, QUASAR_FILENAME_LEN,
};

// SAFETY: these are the bindgen-generated mirrors of the C key structs. They
// are plain data with no padding -- the parity test pins that -- and no
// invalid bit patterns.
unsafe impl Pod for exec_key {}
unsafe impl Pod for cidr_data {}
unsafe impl Pod for cidr_data6 {}

const FNV_PRIME: u64 = 0x100000001b3;
const FNV_OFFSET1: u64 = 0xcbf29ce484222325;
const FNV_OFFSET2: u64 = 0x84222325cbf29ce4;

/// Hash a path exactly as the probe does.
///
/// The probe hashes what `bpf_probe_read_kernel_str` returned, and that length
/// *includes* the NUL terminator -- so the terminator is part of the hash. Miss
/// that and every lookup silently misses. `tests/hash_parity.rs` compares this
/// against the C directly rather than trusting the description.
pub fn path_hash(path: &str) -> [u8; 16] {
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    hash_bytes(&bytes)
}

pub fn hash_bytes(bytes: &[u8]) -> [u8; 16] {
    let mut h1 = FNV_OFFSET1;
    let mut h2 = FNV_OFFSET2;

    for &byte in bytes.iter().take(QUASAR_FILENAME_LEN as usize) {
        h1 = (h1 ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
        h2 = (h2 ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
        h2 = h2.rotate_left(1);
    }

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&h1.to_ne_bytes());
    out[8..].copy_from_slice(&h2.to_ne_bytes());
    out
}

pub struct MapSync {
    exec_allow: HashMap<MapData, exec_key, u8>,
    egress_allow: LpmTrie<MapData, cidr_data, u8>,
    egress_allow6: LpmTrie<MapData, cidr_data6, u8>,
}

/// What one sync pass wrote.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub exec: usize,
    pub egress: usize,
    /// Rules the maps could not hold. Reported rather than swallowed: a full
    /// map means events that should have been filtered are still arriving.
    pub rejected: usize,
}

impl MapSync {
    pub fn take(exec_ebpf: &mut Ebpf, connect_ebpf: &mut Ebpf) -> Result<Self> {
        Ok(Self {
            exec_allow: HashMap::try_from(
                exec_ebpf
                    .take_map("exec_allow")
                    .context("no exec_allow map in the exec object")?,
            )?,
            egress_allow: LpmTrie::try_from(
                connect_ebpf
                    .take_map("egress_allow")
                    .context("no egress_allow map in the connect object")?,
            )?,
            egress_allow6: LpmTrie::try_from(
                connect_ebpf
                    .take_map("egress_allow6")
                    .context("no egress_allow6 map in the connect object")?,
            )?,
        })
    }

    /// Write one container's allow rules under the cgroup id it is running as.
    ///
    /// Only `allow` rules go down. A deny rule is the absence of an allow as
    /// far as the kernel is concerned -- it must reach userspace to be alerted
    /// on, so filtering it out would hide exactly what it exists to catch.
    pub fn apply(&mut self, cgroup_id: u64, policy: &Policy) -> Applied {
        let mut applied = Applied::default();

        for rule in &policy.exec.allow {
            if self.allow_exec(cgroup_id, rule).is_ok() {
                applied.exec += 1;
            } else {
                applied.rejected += 1;
            }
        }

        for rule in &policy.egress.allow {
            if self.allow_egress(cgroup_id, rule).is_ok() {
                applied.egress += 1;
            } else {
                applied.rejected += 1;
            }
        }

        applied
    }

    fn allow_exec(&mut self, cgroup_id: u64, rule: &ExecRule) -> Result<()> {
        let key = exec_key {
            cgroup_id,
            path_hash: path_hash(&rule.path),
        };
        self.exec_allow.insert(key, 1, 0)?;
        Ok(())
    }

    fn allow_egress(&mut self, cgroup_id: u64, rule: &EgressRule) -> Result<()> {
        let prefix = QUASAR_CGROUP_PREFIX_BITS + u32::from(rule.cidr.prefix_len());

        match rule.cidr {
            IpNet::V4(net) => {
                let key = cidr_data {
                    cgroup_id: cgroup_id.to_ne_bytes(),
                    addr: net.network().octets(),
                };
                self.egress_allow.insert(&Key::new(prefix, key), 1, 0)?;
            }
            IpNet::V6(net) => {
                let key = cidr_data6 {
                    cgroup_id: cgroup_id.to_ne_bytes(),
                    addr: net.network().octets(),
                };
                self.egress_allow6.insert(&Key::new(prefix, key), 1, 0)?;
            }
        }
        Ok(())
    }

    /// Drop a container's entries. Its cgroup id is gone once it stops, and a
    /// reused id must not inherit the previous container's allowlist.
    pub fn clear(&mut self, cgroup_id: u64, policy: &Policy) {
        for rule in &policy.exec.allow {
            let key = exec_key {
                cgroup_id,
                path_hash: path_hash(&rule.path),
            };
            let _ = self.exec_allow.remove(&key);
        }

        for rule in &policy.egress.allow {
            let prefix = QUASAR_CGROUP_PREFIX_BITS + u32::from(rule.cidr.prefix_len());
            match rule.cidr {
                IpNet::V4(net) => {
                    let key = cidr_data {
                        cgroup_id: cgroup_id.to_ne_bytes(),
                        addr: net.network().octets(),
                    };
                    let _ = self.egress_allow.remove(&Key::new(prefix, key));
                }
                IpNet::V6(net) => {
                    let key = cidr_data6 {
                        cgroup_id: cgroup_id.to_ne_bytes(),
                        addr: net.network().octets(),
                    };
                    let _ = self.egress_allow6.remove(&Key::new(prefix, key));
                }
            }
        }
    }
}

/// Whether a policy has anything worth pushing down.
pub fn has_allow_rules(policy: &Policy) -> bool {
    !policy.exec.allow.is_empty() || !policy.egress.allow.is_empty()
}

/// Manual denials never reach the maps, so they are worth surfacing at load
/// time -- a human wrote them and needs to know they are being honoured in
/// userspace rather than in the kernel.
pub fn manual_deny_count(policy: &Policy) -> usize {
    policy
        .exec
        .deny
        .iter()
        .filter(|rule| rule.source.is_manual())
        .count()
        + policy
            .egress
            .deny
            .iter()
            .filter(|rule| rule.source == Source::Manual)
            .count()
}
