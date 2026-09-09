//! Arming, and the lease that makes it safe.
//!
//! Arming is per cgroup and carries an absolute expiry the probe checks for
//! itself. Userspace renews it on a heartbeat, so arming is something that has
//! to be actively maintained rather than something that has to be actively
//! cleaned up. Kill quasar, and the kernel stops honouring the arming within a
//! lease -- without userspace doing anything, because there is nothing left of
//! it to do anything.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, MapData},
    Ebpf, Pod,
};

use crate::{
    event::{enforce_state, QUASAR_MODE_DRY_RUN},
    sink::record::monotonic_ns,
};

// SAFETY: the bindgen mirror of the C struct. Plain data, no padding beyond
// the named reserved bytes, and no invalid bit patterns.
unsafe impl Pod for enforce_state {}

/// How long the kernel honours an arming without hearing from userspace.
pub const LEASE: Duration = Duration::from_secs(30);

/// How often userspace renews. Well inside the lease, so an unlucky scheduling
/// delay cannot disarm by accident, and short enough that a dead quasar stops
/// being enforced against promptly.
pub const RENEW: Duration = Duration::from_secs(10);

pub fn lease_from(now_ns: u64) -> u64 {
    now_ns.saturating_add(LEASE.as_nanos() as u64)
}

pub struct Armory {
    map: HashMap<MapData, u64, enforce_state>,
    /// The containers the operator asked for, whether or not they are running.
    requested: BTreeSet<String>,
    /// What is armed right now, and under which cgroup id.
    armed: BTreeMap<String, u64>,
}

impl Armory {
    pub fn take(ebpf: &mut Ebpf, requested: BTreeSet<String>) -> Result<Self> {
        Ok(Self {
            map: HashMap::try_from(
                ebpf.take_map("enforce")
                    .context("no enforce map in the exec object")?,
            )?,
            requested,
            armed: BTreeMap::new(),
        })
    }

    pub fn is_requested(&self, name: &str) -> bool {
        self.requested.contains(name)
    }

    pub fn requested(&self) -> impl Iterator<Item = &String> {
        self.requested.iter()
    }

    pub fn armed_count(&self) -> usize {
        self.armed.len()
    }

    /// Arm a container under the cgroup id it is running as now.
    ///
    /// A container's cgroup id changes every time it starts, so this is called
    /// again on each start rather than once at boot.
    pub fn arm(&mut self, name: &str, cgroup_id: u64) -> Result<bool> {
        if !self.requested.contains(name) {
            return Ok(false);
        }

        self.write(cgroup_id)?;
        self.armed.insert(name.to_owned(), cgroup_id);
        Ok(true)
    }

    pub fn disarm(&mut self, name: &str) -> Result<()> {
        if let Some(cgroup_id) = self.armed.remove(name) {
            // Removed rather than set to off: an entry that exists only to say
            // "not armed" is a thing that can be got wrong.
            self.map
                .remove(&cgroup_id)
                .with_context(|| format!("disarming {name}"))?;
        }
        Ok(())
    }

    /// Push every lease forward. The heartbeat.
    pub fn renew(&mut self) -> Result<()> {
        let armed: Vec<u64> = self.armed.values().copied().collect();
        for cgroup_id in armed {
            self.write(cgroup_id)?;
        }
        Ok(())
    }

    fn write(&mut self, cgroup_id: u64) -> Result<()> {
        let state = enforce_state {
            expires_at_ns: lease_from(monotonic_ns()?),
            mode: QUASAR_MODE_DRY_RUN as u8,
            _reserved: [0; 7],
        };
        self.map
            .insert(cgroup_id, state, 0)
            .context("writing the arming map")
    }
}
