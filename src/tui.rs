//! The `quasar top` screen.
//!
//! State and drawing are separate. [`App`] is a plain struct that a [`Frame`]
//! is applied to, and everything below `draw` only reads it -- so what the
//! screen decides can be tested without a terminal, which is the half that
//! holds the logic.

use std::{collections::VecDeque, path::Path, time::Duration};

use anyhow::{bail, Context, Result};
use crossterm::{
    event::{Event as TermEvent, EventStream, KeyCode, KeyEvent, KeyEventKind},
    tty::IsTty,
};
use futures_util::StreamExt;
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Row, Table},
    DefaultTerminal, Frame as Canvas,
};

use crate::{
    event::Outcome,
    policy::Decision,
    sink::{
        record::{Body, Record},
        socket::{Client, Frame},
    },
    stats::{Counts, Snapshot},
};

/// How much history the tail keeps. Bounded, because a view that grows without
/// limit is a memory leak wearing a user interface.
const TAIL: usize = 500;

/// Drawing is on a timer rather than per event: a burst would otherwise redraw
/// the screen thousands of times a second to show frames nobody can read.
const REDRAW: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Normal,
    Warning,
    Critical,
}

/// Kept separate from the colour it maps to, so the rule is testable.
pub fn severity(decision: Option<Decision>) -> Severity {
    match decision {
        Some(Decision::Denied) => Severity::Critical,
        Some(Decision::Unbaselined) => Severity::Warning,
        Some(Decision::Allowed) | None => Severity::Normal,
    }
}

/// An exec enforcement objected to outranks whatever the policy alone said --
/// a would-block is what enforcement will actually do to this container.
pub fn severity_of(record: &Record, decision: Option<Decision>) -> Severity {
    match &record.body {
        Body::Exec { outcome, .. } if outcome.is_enforcement() => Severity::Critical,
        _ => severity(decision),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Event {
        record: Record,
        decision: Option<Decision>,
    },
    /// Frames this client lost. Kept in the tail where it happened, so the gap
    /// is visible in the history rather than only as a number in the header.
    Gap { missed: u64 },
}

#[derive(Debug)]
pub struct App {
    pub snapshot: Snapshot,
    pub missed: u64,
    tail: VecDeque<Entry>,
    capacity: usize,
}

impl Default for App {
    fn default() -> Self {
        Self::new(TAIL)
    }
}

impl App {
    pub fn new(capacity: usize) -> Self {
        Self {
            snapshot: Snapshot::default(),
            missed: 0,
            tail: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn apply(&mut self, frame: Frame) {
        match frame {
            Frame::Event { record, decision } => self.push(Entry::Event { record, decision }),
            Frame::Stats { snapshot } => self.snapshot = snapshot,
            Frame::Lagged { missed } => {
                self.missed += missed;
                self.push(Entry::Gap { missed });
            }
        }
    }

    fn push(&mut self, entry: Entry) {
        while self.tail.len() >= self.capacity {
            self.tail.pop_front();
        }
        self.tail.push_back(entry);
    }

    /// Oldest first.
    pub fn tail(&self) -> impl DoubleEndedIterator<Item = &Entry> {
        self.tail.iter()
    }

    /// The newest `count` entries, oldest first -- what fits on the screen.
    pub fn recent(&self, count: usize) -> impl Iterator<Item = &Entry> {
        self.tail.iter().skip(self.tail.len().saturating_sub(count))
    }

    pub fn len(&self) -> usize {
        self.tail.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tail.is_empty()
    }

    /// Busiest first, so whatever is worth looking at is at the top. Ties
    /// break on name, so the table does not shuffle between redraws.
    pub fn sources(&self) -> Vec<(&str, &Counts)> {
        let mut rows: Vec<(&str, &Counts)> = self
            .snapshot
            .by_source
            .iter()
            .map(|(name, counts)| (name.as_str(), counts))
            .collect();

        rows.sort_by(|a, b| {
            volume(b.1)
                .cmp(&volume(a.1))
                .then_with(|| b.1.alerts.cmp(&a.1.alerts))
                .then_with(|| a.0.cmp(b.0))
        });
        rows
    }
}

fn volume(counts: &Counts) -> u64 {
    counts.execs + counts.connects
}

pub async fn run(path: &Path) -> Result<()> {
    // Checked before anything else: initialising a terminal that is not there
    // panics deep inside ratatui, and a redirected `quasar top` deserves a
    // sentence telling it what to do instead.
    if !std::io::stdout().is_tty() {
        bail!("quasar top needs a terminal -- use --plain to pipe or redirect the stream");
    }

    // Connect before taking over the terminal, so a failure to connect prints
    // an ordinary error instead of flashing an empty screen.
    let mut client = Client::connect(path).await?;

    install_panic_hook();
    let mut terminal = ratatui::try_init().context("taking over the terminal")?;
    let result = drive(&mut terminal, &mut client).await;
    ratatui::restore();
    result
}

/// The same stream, one line per frame.
///
/// A screen that cannot be piped into `grep` is worse than one that can, and
/// this is also what the acceptance suite drives -- asserting on a rendered
/// terminal would test the drawing, which the unit tests already cover, rather
/// than the property the phase is accepted on.
pub async fn run_plain(path: &Path) -> Result<()> {
    let mut client = Client::connect(path).await?;
    eprintln!("quasar: attached to {}", path.display());

    while let Some(frame) = client.next().await? {
        match frame {
            Frame::Event { record, decision } => {
                let mark = match severity(decision) {
                    Severity::Critical => "DENIED      ",
                    Severity::Warning => "UNBASELINED ",
                    Severity::Normal => "            ",
                };
                println!("[{}] {mark}{}", record.time, describe(&record));
            }
            Frame::Stats { snapshot } => println!(
                "-- {} execs, {} connects, {} alerts across {} sources --",
                snapshot.total.execs,
                snapshot.total.connects,
                snapshot.total.alerts,
                snapshot.by_source.len()
            ),
            Frame::Lagged { missed } => println!("-- {missed} events missed --"),
        }
    }

    eprintln!("quasar: the daemon closed the connection");
    Ok(())
}

/// A panic in raw mode with the alternate screen up leaves the shell unusable
/// and the message invisible. Restore first, then panic normally.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        previous(info);
    }));
}

async fn drive(terminal: &mut DefaultTerminal, client: &mut Client) -> Result<()> {
    let mut app = App::default();
    let mut keys = EventStream::new();
    let mut redraw = tokio::time::interval(REDRAW);

    loop {
        tokio::select! {
            frame = client.next() => match frame? {
                Some(frame) => app.apply(frame),
                None => break,
            },
            key = keys.next() => {
                if let Some(Ok(TermEvent::Key(key))) = key {
                    if quits(&key) {
                        break;
                    }
                }
            }
            _ = redraw.tick() => {
                terminal.draw(|canvas| draw(&app, canvas))?;
            }
        }
    }

    Ok(())
}

/// Raw mode swallows the terminal's own interrupt, so ctrl-c has to be handled
/// here or the only way out is another terminal.
fn quits(key: &KeyEvent) -> bool {
    key.kind == KeyEventKind::Press
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            || (key.code == KeyCode::Char('c')
                && key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL)))
}

pub fn draw(app: &App, canvas: &mut Canvas) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(canvas.area());

    let [left, right] =
        Layout::horizontal([Constraint::Percentage(38), Constraint::Percentage(62)]).areas(body);

    canvas.render_widget(totals(app), header);
    canvas.render_widget(sources(app), left);
    canvas.render_widget(events(app, right.height.saturating_sub(2) as usize), right);
    canvas.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " q quit ",
            Style::new().fg(Color::DarkGray),
        ))),
        footer,
    );
}

fn totals(app: &App) -> Paragraph<'_> {
    let total = &app.snapshot.total;
    let mut spans = vec![
        Span::raw(format!("{} execs   ", total.execs)),
        Span::raw(format!("{} connects   ", total.connects)),
        Span::styled(
            format!("{} alerts", total.alerts),
            if total.alerts > 0 {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new()
            },
        ),
        Span::raw(format!("   {} sources", app.snapshot.by_source.len())),
    ];

    if app.missed > 0 {
        spans.push(Span::styled(
            format!("   {} frames missed", app.missed),
            Style::new().fg(Color::Magenta),
        ));
    }

    Paragraph::new(Line::from(spans)).block(Block::bordered().title(" quasar "))
}

fn sources(app: &App) -> Table<'_> {
    let rows = app.sources().into_iter().map(|(name, counts)| {
        Row::new(vec![
            name.to_owned(),
            counts.execs.to_string(),
            counts.connects.to_string(),
            counts.alerts.to_string(),
        ])
        .style(if counts.alerts > 0 {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new()
        })
    });

    Table::new(
        rows,
        [
            Constraint::Min(12),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(vec!["source", "execs", "connects", "alerts"])
            .style(Style::new().add_modifier(Modifier::BOLD)),
    )
    .block(Block::bordered().title(" containers "))
}

fn events(app: &App, height: usize) -> Paragraph<'_> {
    let lines: Vec<Line> = app.recent(height.max(1)).map(render_entry).collect();

    Paragraph::new(lines).block(Block::bordered().title(" events "))
}

fn render_entry(entry: &Entry) -> Line<'_> {
    match entry {
        Entry::Gap { missed } => Line::from(Span::styled(
            format!("-- {missed} events missed --"),
            Style::new().fg(Color::Magenta),
        )),
        Entry::Event { record, decision } => Line::from(Span::styled(
            describe(record),
            match severity_of(record, *decision) {
                Severity::Critical => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                Severity::Warning => Style::new().fg(Color::Yellow),
                Severity::Normal => Style::new(),
            },
        )),
    }
}

pub fn describe(record: &Record) -> String {
    let what = match &record.body {
        Body::Exec { path, outcome } => match outcome {
            Outcome::WouldBlock => format!("WOULD BLOCK exec {path}"),
            Outcome::Blocked => format!("BLOCKED exec {path}"),
            Outcome::Observed => format!("exec {path}"),
        },
        Body::Connect { proto, dest, port } => format!("connect {proto} {dest}:{port}"),
    };
    format!(
        "{:<22} {:<10} {what}",
        truncate(&record.source, 22),
        truncate(&record.comm, 10)
    )
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    text.chars()
        .take(width.saturating_sub(1))
        .chain(['…'])
        .collect()
}
