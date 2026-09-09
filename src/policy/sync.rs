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

/// The allowlist key for a path, or `None` if the path cannot be one.
///
/// The probe reads the path with `bpf_probe_read_kernel_str` into a buffer of
/// exactly this size, so what it looks up is the path plus its NUL. A path
/// that would not fit is refused here rather than truncated: a prefix could
/// name a different binary, and under enforcement that is an execution.
pub fn exec_key_for(cgroup_id: u64, path: &str) -> Option<exec_key> {
    let bytes = path.as_bytes();
    if bytes.len() + 1 > QUASAR_FILENAME_LEN as usize {
        return None;
    }

    let mut key = exec_key {
        cgroup_id,
        path: [0; QUASAR_FILENAME_LEN as usize],
    };
    key.path[..bytes.len()].copy_from_slice(bytes);
    Some(key)
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
        let key = exec_key_for(cgroup_id, &rule.path)
            .with_context(|| format!("{} does not fit an allowlist key", rule.path))?;
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
            if let Some(key) = exec_key_for(cgroup_id, &rule.path) {
                let _ = self.exec_allow.remove(&key);
            }
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
