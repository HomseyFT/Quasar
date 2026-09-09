//! The `quasar top` server.
//!
//! The daemon runs headless. Attaching a client, killing one mid-stream, or
//! attaching twenty must not change what the monitor does, so nothing on the
//! publishing side ever awaits a client:
//!
//! - fan-out is a broadcast, and a client that stops reading fills its own
//!   queue and is told the size of the gap rather than slowing the monitor;
//! - a client's write blocking blocks only that client's task;
//! - a client that dies is dropped, and the error is not propagated.

use std::{
    fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::broadcast,
};

use super::record::Record;
use crate::stats::{Counters, Snapshot};

pub const DEFAULT_SOCKET: &str = "/run/quasar.sock";

/// How far a client may fall behind before it starts losing frames. Large
/// enough to absorb a burst, small enough that a wedged client cannot hold
/// megabytes of records alive.
const BACKLOG: usize = 1024;

const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// One line of the protocol. This is the stream's framing, deliberately not
/// the log's format: `Record` is what a line of the durable log is, and
/// wrapping it here keeps the two free to differ.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "frame", rename_all = "lowercase")]
pub enum Frame {
    Event {
        record: Record,
    },
    Stats {
        snapshot: Snapshot,
    },
    /// This client fell behind and lost frames. Sent rather than swallowed: a
    /// live view with a silent gap in it is worse than one that admits the gap.
    Lagged {
        missed: u64,
    },
}

/// The monitor's end. Cloneable, cheap, and never blocking.
#[derive(Clone)]
pub struct Publisher {
    events: broadcast::Sender<Record>,
    counters: Arc<Mutex<Counters>>,
}

impl Publisher {
    pub fn publish(&self, record: &Record, alerted: bool) {
        if let Ok(mut counters) = self.counters.lock() {
            counters.record(record, alerted);
        }

        // Cloning only when somebody is listening keeps the headless case --
        // the normal one -- free.
        if self.events.receiver_count() > 0 {
            // Errors only when the last receiver went away between the check
            // and the send. Nothing to do about that, and nothing to report.
            let _ = self.events.send(record.clone());
        }
    }
}

/// Bind the socket and start accepting clients.
pub fn serve(path: &Path) -> Result<Publisher> {
    // A socket file left behind by a crashed run makes bind fail with
    // EADDRINUSE. Removing it is safe; removing anything else is not.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)
            .with_context(|| format!("removing the stale socket at {}", path.display()))?,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspecting {}", path.display())),
    }

    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;

    // This stream is security telemetry: every exec and every destination on
    // the host. Nothing but root reads it.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;

    let (events, _) = broadcast::channel(BACKLOG);
    let counters = Arc::new(Mutex::new(Counters::default()));

    tokio::spawn(accept(listener, events.clone(), Arc::clone(&counters)));

    Ok(Publisher { events, counters })
}

async fn accept(
    listener: UnixListener,
    events: broadcast::Sender<Record>,
    counters: Arc<Mutex<Counters>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let receiver = events.subscribe();
                let counters = Arc::clone(&counters);
                // A client ending is routine -- it was closed, or it died.
                tokio::spawn(async move {
                    let _ = talk(stream, receiver, counters).await;
                });
            }
            Err(error) => {
                eprintln!("quasar: rejecting a client: {error}");
                // Do not spin if the listener is persistently unhappy.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn talk(
    mut stream: UnixStream,
    mut events: broadcast::Receiver<Record>,
    counters: Arc<Mutex<Counters>>,
) -> Result<()> {
    // Immediately, so a client that just attached shows real numbers instead
    // of zeros until the first tick.
    send(&mut stream, &stats(&counters)).await?;

    let mut ticker =
        tokio::time::interval_at(tokio::time::Instant::now() + STATS_INTERVAL, STATS_INTERVAL);

    loop {
        tokio::select! {
            received = events.recv() => match received {
                Ok(record) => send(&mut stream, &Frame::Event { record }).await?,
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    send(&mut stream, &Frame::Lagged { missed }).await?;
                }
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            _ = ticker.tick() => send(&mut stream, &stats(&counters)).await?,
        }
    }
}

fn stats(counters: &Mutex<Counters>) -> Frame {
    Frame::Stats {
        snapshot: counters.lock().map(|c| c.snapshot()).unwrap_or_default(),
    }
}

async fn send(stream: &mut UnixStream, frame: &Frame) -> Result<()> {
    let mut line = serde_json::to_vec(frame).context("serialising a frame")?;
    line.push(b'\n');
    stream.write_all(&line).await.context("writing to a client")
}

/// The client's end.
pub struct Client {
    reader: BufReader<UnixStream>,
    line: String,
}

impl Client {
    /// Connect. A client sees events published from the moment the daemon
    /// accepts it, not from when `connect` returned -- those are different
    /// instants, and a broadcast only reaches receivers that already exist.
    /// The immediate snapshot is the first frame, so receiving it is proof the
    /// subscription is live.
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .await
            .with_context(|| format!("connecting to {}", path.display()))?;

        Ok(Self {
            reader: BufReader::new(stream),
            line: String::new(),
        })
    }

    /// The next frame, or `None` when the daemon closed the connection.
    pub async fn next(&mut self) -> Result<Option<Frame>> {
        self.line.clear();
        if self.reader.read_line(&mut self.line).await? == 0 {
            return Ok(None);
        }
        serde_json::from_str(&self.line)
            .map(Some)
            .context("decoding a frame")
    }
}
