//! Arming, and the rails that make it survivable.
//!
//! Arming is per cgroup and carries an absolute expiry the probe checks for
//! itself. Userspace renews it on a heartbeat, so arming is something that has
//! to be actively maintained rather than something that has to be actively
//! cleaned up. Kill quasar and the kernel stops honouring the arming within a
//! lease -- without userspace doing anything, because there is nothing left of
//! it to do anything.
//!
//! `--revert-after` is the same mechanism rather than a second one: past the
//! deadline the heartbeat stops, and the lease already knows how to expire.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{HashMap, MapData},
    Ebpf, Pod,
};

use crate::{
    event::{enforce_state, QUASAR_MODE_DRY_RUN, QUASAR_MODE_ENFORCE, QUASAR_MODE_OFF},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Report what enforcement would do. Nothing is ever prevented.
    DryRun,
    /// Refuse a disallowed exec.
    Enforce,
}

impl Mode {
    fn raw(self) -> u8 {
        match self {
            Self::DryRun => QUASAR_MODE_DRY_RUN as u8,
            Self::Enforce => QUASAR_MODE_ENFORCE as u8,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DryRun => "dry run",
            Self::Enforce => "enforcing",
        }
    }
}

/// What one heartbeat found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Renewal {
    /// Containers the kernel disarmed because the deadman tripped. Reported
    /// rather than quietly re-armed: something is wrong with their policy.
    pub tripped: Vec<String>,
    /// The `--revert-after` deadline passed on this beat.
    pub reverted: bool,
}

pub struct Armory {
    map: HashMap<MapData, u64, enforce_state>,
    requested: BTreeMap<String, Mode>,
    /// What is armed right now, and under which cgroup id.
    armed: BTreeMap<String, u64>,
    revert_at_ns: Option<u64>,
    reverted: bool,
}

impl Armory {
    pub fn take(
        ebpf: &mut Ebpf,
        requested: BTreeMap<String, Mode>,
        revert_after: Option<Duration>,
    ) -> Result<Self> {
        let revert_at_ns = match revert_after {
            Some(after) => Some(monotonic_ns()?.saturating_add(after.as_nanos() as u64)),
            None => None,
        };

        Ok(Self {
            map: HashMap::try_from(
                ebpf.take_map("enforce")
                    .context("no enforce map in the exec object")?,
            )?,
            requested,
            armed: BTreeMap::new(),
            revert_at_ns,
            reverted: false,
        })
    }

    pub fn mode_for(&self, name: &str) -> Option<Mode> {
        self.requested.get(name).copied()
    }

    pub fn requested(&self) -> impl Iterator<Item = (&String, &Mode)> {
        self.requested.iter()
    }

    pub fn armed_count(&self) -> usize {
        self.armed.len()
    }

    /// Stop asking for a container. Used when its policy could not govern it.
    pub fn forget(&mut self, name: &str) {
        self.requested.remove(name);
    }

    /// Arm a container under the cgroup id it is running as now.
    ///
    /// A container's cgroup id changes every time it starts, so this is called
    /// again on each start rather than once at boot.
    pub fn arm(&mut self, name: &str, cgroup_id: u64) -> Result<Option<Mode>> {
        if self.reverted {
            return Ok(None);
        }
        let Some(mode) = self.requested.get(name).copied() else {
            return Ok(None);
        };

        let state = enforce_state {
            expires_at_ns: lease_from(monotonic_ns()?),
            window_start_ns: 0,
            blocks: 0,
            mode: mode.raw(),
            _reserved: [0; 3],
        };
        self.map
            .insert(cgroup_id, state, 0)
            .with_context(|| format!("arming {name}"))?;
        self.armed.insert(name.to_owned(), cgroup_id);

        Ok(Some(mode))
    }

    pub fn disarm(&mut self, name: &str) -> Result<()> {
        if let Some(cgroup_id) = self.armed.remove(name) {
            // Removed rather than set to off: an entry that exists only to say
            // "not armed" is a thing that can be got wrong.
            let _ = self.map.remove(&cgroup_id);
        }
        Ok(())
    }

    /// Push every lease forward, and notice anything the kernel disarmed.
    pub fn renew(&mut self) -> Result<Renewal> {
        let mut renewal = Renewal::default();

        if self.reverted {
            return Ok(renewal);
        }

        if self
            .revert_at_ns
            .is_some_and(|at| monotonic_ns().is_ok_and(|now| now >= at))
        {
            self.reverted = true;
            renewal.reverted = true;
            // Both: remove the entries so it takes effect now, and stop
            // renewing so it takes effect anyway if the removal fails.
            let names: Vec<String> = self.armed.keys().cloned().collect();
            for name in names {
                self.disarm(&name)?;
            }
            return Ok(renewal);
        }

        let now = monotonic_ns()?;
        for (name, cgroup_id) in self.armed.clone() {
            // Read before write. The kernel disarms a tripped container by
            // setting the mode off, and a heartbeat that blindly rewrote the
            // state would resurrect enforcement the kernel just abandoned --
            // and reset the deadman's counters while doing it.
            let Ok(mut state) = self.map.get(&cgroup_id, 0) else {
                renewal.tripped.push(name.clone());
                self.armed.remove(&name);
                continue;
            };

            if u32::from(state.mode) == QUASAR_MODE_OFF {
                renewal.tripped.push(name.clone());
                self.armed.remove(&name);
                continue;
            }

            state.expires_at_ns = lease_from(now);
            self.map
                .insert(cgroup_id, state, 0)
                .with_context(|| format!("renewing the lease for {name}"))?;
        }

        Ok(renewal)
    }
}

/// Parse `30s`, `15m`, `2h`, `7d`.
///
/// Written out rather than pulled in: the whole grammar is one number and one
/// letter, and a dependency that parses more than that would accept more than
/// that.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );

    if digits.is_empty() {
        bail!("{text:?} has no number in it -- try 30s, 15m, 2h or 7d");
    }

    let count: u64 = digits.parse().with_context(|| format!("{digits:?}"))?;
    let seconds = match unit {
        "s" | "" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        other => bail!("{other:?} is not a unit -- use s, m, h or d"),
    };

    count
        .checked_mul(seconds)
        .map(Duration::from_secs)
        .with_context(|| format!("{text:?} is too long a duration to represent"))
}

/// Which containers were asked for, from repeated flags.
pub fn requests(dry_run: &[String], enforce: &[String]) -> Result<BTreeMap<String, Mode>> {
    let mut requested = BTreeMap::new();
    for name in dry_run {
        requested.insert(name.clone(), Mode::DryRun);
    }

    let dry: BTreeSet<&String> = dry_run.iter().collect();
    for name in enforce {
        if dry.contains(name) {
            bail!("{name} is named for both a dry run and enforcement -- pick one");
        }
        requested.insert(name.clone(), Mode::Enforce);
    }

    Ok(requested)
}
