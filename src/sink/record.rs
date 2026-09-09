//! The event record every consumer shares.
//!
//! The durable log defined this first, and then `quasar top` needed the same
//! value. Two consumers formatting an event their own way is how a log and a
//! live view drift apart, so the definition lives here and both read it.

use std::net::IpAddr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    event::{ConnectEvent, ExecEvent, Outcome},
    registry::Attribution,
};

/// How well the event was attributed. Kept in the record because `learn` must
/// only build policy from events it can actually name a container for, and
/// because a rise in `unknown` is itself worth noticing later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Attributed {
    /// Container known by name. The only kind `learn` will build policy from.
    Named,
    /// Container id known, name not. Raced the Docker event stream.
    Container,
    /// A host process, definitively not a container.
    Host,
    /// Neither the cgroup nor the process could be found.
    Unknown,
}

impl From<&Attribution> for Attributed {
    fn from(attribution: &Attribution) -> Self {
        match attribution {
            Attribution::Named { .. } => Self::Named,
            Attribution::Container { .. } => Self::Container,
            Attribution::Host { .. } => Self::Host,
            Attribution::Unknown { .. } => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Body {
    Exec {
        path: String,
        /// Absent for an ordinary observation, so the common line stays quiet
        /// and logs written before enforcement existed still parse.
        #[serde(default, skip_serializing_if = "Outcome::is_observed")]
        outcome: Outcome,
    },
    Connect {
        proto: String,
        dest: IpAddr,
        port: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// RFC 3339 wall clock.
    pub time: String,
    /// What the attribution resolved to, in display form.
    pub source: String,
    pub attributed: Attributed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    #[serde(flatten)]
    pub body: Body,
}

/// Turns a probe timestamp into wall clock.
///
/// Ring buffer timestamps are `bpf_ktime_get_ns` -- monotonic since boot. A
/// durable log needs wall clock, so the two clocks are sampled once here and
/// the difference applied to every event.
pub struct Clock {
    boot_offset_ns: i128,
}

impl Clock {
    pub fn new() -> Result<Self> {
        Ok(Self {
            boot_offset_ns: clock_ns(libc::CLOCK_REALTIME)? - clock_ns(libc::CLOCK_MONOTONIC)?,
        })
    }

    pub fn exec(&self, who: &Attribution, event: &ExecEvent) -> Record {
        Record {
            time: self.wall_clock(event.timestamp_ns),
            source: who.to_string(),
            attributed: who.into(),
            container_id: who.container_id().map(str::to_owned),
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: event.comm().into_owned(),
            body: Body::Exec {
                path: event.filename().into_owned(),
                outcome: event.outcome(),
            },
        }
    }

    pub fn connect(&self, who: &Attribution, event: &ConnectEvent) -> Record {
        Record {
            time: self.wall_clock(event.timestamp_ns),
            source: who.to_string(),
            attributed: who.into(),
            container_id: who.container_id().map(str::to_owned),
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            comm: event.comm().into_owned(),
            body: Body::Connect {
                proto: event.protocol_name().to_owned(),
                dest: event.destination(),
                port: event.dport,
            },
        }
    }

    fn wall_clock(&self, monotonic_ns: u64) -> String {
        let nanos = self.boot_offset_ns + i128::from(monotonic_ns);
        jiff::Timestamp::from_nanosecond(nanos)
            .map(|t| t.to_string())
            .unwrap_or_else(|_| format!("+{monotonic_ns}ns"))
    }
}

/// The clock the probes stamp events with, and the one arming expiries are
/// expressed in. Kept here because this is where clock reading lives.
pub fn monotonic_ns() -> Result<u64> {
    Ok(clock_ns(libc::CLOCK_MONOTONIC)?.max(0) as u64)
}

fn clock_ns(clock: libc::clockid_t) -> Result<i128> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, initialised timespec for the duration of the call.
    let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime");
    }
    Ok(i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec))
}
