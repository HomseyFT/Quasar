//! Alert push.
//!
//! Everything that reaches this module has already survived kernel-side
//! filtering and been judged unbaselined or denied, so the volume is low by
//! construction. It is not low on the day a policy is wrong, which is what the
//! suppressor is for: an alert per event would send thousands of notifications
//! to a phone and teach its owner to swipe them away.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use crate::policy::Decision;

pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Two events with the same key are the same alert. The subject is what a
/// human would read as "the thing that happened" -- a path, or a destination.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AlertKey {
    pub container: String,
    pub decision: Decision,
    pub subject: String,
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub key: AlertKey,
    /// Who did it. Not part of the key: the same binary run by twenty pids is
    /// one alert, not twenty.
    pub detail: String,
}

impl Alert {
    pub fn render(&self, suppressed: u64) -> Message {
        render(&self.key, &self.detail, suppressed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Send it, and mention this many that were held back since the last send.
    Send {
        suppressed: u64,
    },
    Hold,
}

struct Entry {
    window_started: Instant,
    suppressed: u64,
}

/// Collapses repeats of the same alert into one notification per window.
///
/// `Instant` is passed in rather than read, so the window is testable without
/// sleeping through it.
pub struct Suppressor {
    window: Duration,
    seen: HashMap<AlertKey, Entry>,
}

impl Suppressor {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            seen: HashMap::new(),
        }
    }

    pub fn admit(&mut self, key: &AlertKey, now: Instant) -> Admit {
        match self.seen.get_mut(key) {
            None => {
                self.seen.insert(
                    key.clone(),
                    Entry {
                        window_started: now,
                        suppressed: 0,
                    },
                );
                Admit::Send { suppressed: 0 }
            }
            Some(entry) if now.duration_since(entry.window_started) < self.window => {
                entry.suppressed += 1;
                Admit::Hold
            }
            Some(entry) => {
                let suppressed = std::mem::take(&mut entry.suppressed);
                entry.window_started = now;
                Admit::Send { suppressed }
            }
        }
    }

    /// Alerts whose window closed while events were still being held back.
    ///
    /// Without this a burst that stops is never fully reported -- you would be
    /// told an alert fired and never told it fired ten thousand more times.
    /// Keys that went quiet are evicted here too, which is what bounds the map.
    pub fn expired(&mut self, now: Instant) -> Vec<(AlertKey, u64)> {
        let mut summaries = Vec::new();

        self.seen.retain(|key, entry| {
            if now.duration_since(entry.window_started) < self.window {
                return true;
            }
            if entry.suppressed > 0 {
                summaries.push((key.clone(), std::mem::take(&mut entry.suppressed)));
                entry.window_started = now;
                true
            } else {
                false
            }
        });

        summaries
    }
}

/// A rendered notification, separate from sending it so the wording can be
/// tested without a network.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub title: String,
    pub body: String,
    pub priority: &'static str,
    pub tags: &'static str,
}

/// `detail` is empty for a window summary, where there is no single event to
/// point at -- only a count of the ones nobody was told about.
pub fn render(key: &AlertKey, detail: &str, suppressed: u64) -> Message {
    let (priority, tags, verb) = match key.decision {
        Decision::Denied => ("high", "rotating_light", "denied"),
        Decision::Unbaselined | Decision::Allowed => ("default", "warning", "unbaselined"),
    };

    let mut body = format!("{verb} {}", key.subject);
    if !detail.is_empty() {
        body.push('\n');
        body.push_str(detail);
    }
    if suppressed > 0 {
        body.push_str(&format!("\n+{suppressed} more since the last alert"));
    }

    Message {
        title: format!("quasar: {}", key.container),
        body,
        priority,
        tags,
    }
}

pub struct NtfySink {
    client: reqwest::Client,
    url: String,
}

impl NtfySink {
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .context("building the ntfy client")?,
            url: url.to_owned(),
        })
    }

    pub async fn send(&self, message: &Message) -> Result<()> {
        self.client
            .post(&self.url)
            .header("Title", &message.title)
            .header("Priority", message.priority)
            .header("Tags", message.tags)
            .body(message.body.clone())
            .send()
            .await
            .context("posting to ntfy")?
            .error_for_status()
            .context("ntfy rejected the notification")?;
        Ok(())
    }
}
