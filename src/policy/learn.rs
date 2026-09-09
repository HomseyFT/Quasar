//! Observation -> draft TOML.
//!
//! `learn` reads the durable log rather than watching live. The log is the
//! record you kept anyway, so learning is re-runnable, reviewable against the
//! same input twice, and does not need a week-long process to stay alive.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::Path,
};

use anyhow::{Context, Result};

use super::{Policy, PolicySet};
use crate::sink::record::{Attributed, Body, Record};

#[derive(Debug, Default)]
pub struct ContainerObservations {
    pub exec_paths: BTreeSet<String>,
    pub destinations: BTreeSet<IpAddr>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// Whether a path is stable enough to be worth a policy rule.
///
/// runc re-execs itself through `/proc/self/fd/<n>` on every container start --
/// the CVE-2019-5736 mitigation. The descriptor number varies, so learning it
/// yields a rule that never matches the next start: it fails to suppress the
/// alert *and* adds another dead entry every time. As an allow rule it would
/// also mean "whatever that descriptor points at", which is not something a
/// policy can usefully permit.
///
/// These are still logged and still evaluated; they are just not baselined.
use super::is_baselineable;

/// Kept as a named wrapper because the count it drives is reported to the
/// operator: a large number here means the policy is being learned from paths
/// that will not be there next time.
fn is_stable_path(path: &str) -> bool {
    is_baselineable(path)
}

#[derive(Debug, Default)]
pub struct Observations {
    pub per_container: BTreeMap<String, ContainerObservations>,
    /// Events that named no container: host processes, and the few that raced
    /// attribution. Counted rather than silently discarded, because a large
    /// number here means the policy is being learned from partial data.
    pub unattributable: usize,
    pub malformed_lines: usize,
    /// Execs through a path that cannot be matched again, so not baselined.
    pub unstable_paths: usize,
    pub total: usize,
}

/// Read a JSONL log into per-container observations.
pub fn observe(log: &Path) -> Result<Observations> {
    let file = File::open(log).with_context(|| format!("opening {}", log.display()))?;
    let mut observations = Observations::default();

    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("reading {}", log.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        observations.total += 1;

        let Ok(record) = serde_json::from_str::<Record>(&line) else {
            observations.malformed_lines += 1;
            continue;
        };

        // Policy is keyed by container name, so only a named attribution can
        // contribute to it.
        if record.attributed != Attributed::Named {
            observations.unattributable += 1;
            continue;
        }

        let entry = observations
            .per_container
            .entry(record.source.clone())
            .or_default();

        match record.body {
            Body::Exec { path, .. } => {
                if !is_stable_path(&path) {
                    observations.unstable_paths += 1;
                    continue;
                }
                entry.exec_paths.insert(path);
            }
            Body::Connect { dest, .. } => {
                entry.destinations.insert(dest);
            }
        }

        if entry.first_seen.as_ref().is_none_or(|t| record.time < *t) {
            entry.first_seen = Some(record.time.clone());
        }
        if entry.last_seen.as_ref().is_none_or(|t| record.time > *t) {
            entry.last_seen = Some(record.time);
        }
    }

    Ok(observations)
}

#[derive(Debug, Default)]
pub struct Summary {
    pub containers: usize,
    pub exec_added: usize,
    pub egress_added: usize,
    /// Observations an existing rule already covered. A high number is the
    /// system working: the policy already describes the behaviour.
    pub already_covered: usize,
}

/// Fold observations into a policy directory, preserving every manual entry.
pub fn merge_into(observations: &Observations, dir: &Path) -> Result<Summary> {
    let mut policies = PolicySet::load_dir(dir)?;
    let mut summary = Summary::default();

    for (container, observed) in &observations.per_container {
        let policy = policies.entry(container);
        summary.containers += 1;

        for path in &observed.exec_paths {
            if policy.learn_exec(path) {
                summary.exec_added += 1;
            } else {
                summary.already_covered += 1;
            }
        }

        for dest in &observed.destinations {
            if policy.learn_egress(*dest) {
                summary.egress_added += 1;
            } else {
                summary.already_covered += 1;
            }
        }

        record_window(policy, observed);
    }

    policies.save_dir(dir)?;
    Ok(summary)
}

/// Widen `learned_from` to cover everything the file has now been taught, so
/// the window in the file always describes all of its learned entries.
fn record_window(policy: &mut Policy, observed: &ContainerObservations) {
    let (Some(first), Some(last)) = (&observed.first_seen, &observed.last_seen) else {
        return;
    };

    let (mut start, mut end) = (first.as_str(), last.as_str());
    if let Some((known_start, known_end)) = policy
        .meta
        .learned_from
        .as_deref()
        .and_then(|w| w.split_once('/'))
    {
        if known_start < start {
            start = known_start;
        }
        if known_end > end {
            end = known_end;
        }
    }

    policy.meta.learned_from = Some(format!("{}/{}", day(start), day(end)));
}

/// Dates, not timestamps: the window is for a human reading the file.
fn day(timestamp: &str) -> &str {
    timestamp.split_once('T').map_or(timestamp, |(day, _)| day)
}
