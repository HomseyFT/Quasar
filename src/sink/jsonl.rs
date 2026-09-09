//! The durable event log.
//!
//! This file is both the record of what happened and the input `quasar learn`
//! reads, so [`Record`] is the one definition of an event on disk. One JSON
//! object per line, appended, never rewritten.

use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    net::IpAddr,
    path::Path,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    event::{ConnectEvent, ExecEvent},
    registry::Attribution,
};

/// How well the event was attributed. Kept in the log because `learn` must only
/// build policy from events it can actually name a container for, and because a
/// rise in `unknown` is itself worth noticing later.
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

pub struct JsonlSink {
    writer: BufWriter<File>,
    /// Ring buffer timestamps are `bpf_ktime_get_ns` -- monotonic since boot.
    /// A durable log needs wall clock, so the two clocks are sampled once and
    /// the difference applied to every event.
    boot_offset_ns: i128,
}

impl JsonlSink {
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;

        Ok(Self {
            writer: BufWriter::new(file),
            boot_offset_ns: boot_offset_ns()?,
        })
    }

    pub fn write_exec(&mut self, who: &Attribution, event: &ExecEvent) -> Result<()> {
        self.write(Record {
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
            },
        })
    }

    pub fn write_connect(&mut self, who: &Attribution, event: &ConnectEvent) -> Result<()> {
        self.write(Record {
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
        })
    }

    fn write(&mut self, record: Record) -> Result<()> {
        serde_json::to_writer(&mut self.writer, &record).context("serialising a log record")?;
        self.writer.write_all(b"\n").context("writing the log")?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("flushing the log")
    }

    fn wall_clock(&self, monotonic_ns: u64) -> String {
        let nanos = self.boot_offset_ns + i128::from(monotonic_ns);
        jiff::Timestamp::from_nanosecond(nanos)
            .map(|t| t.to_string())
            .unwrap_or_else(|_| format!("+{monotonic_ns}ns"))
    }
}

/// CLOCK_REALTIME minus CLOCK_MONOTONIC, sampled once.
fn boot_offset_ns() -> Result<i128> {
    Ok(clock_ns(libc::CLOCK_REALTIME)? - clock_ns(libc::CLOCK_MONOTONIC)?)
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
