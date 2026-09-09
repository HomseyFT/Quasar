//! The screen's decisions, without a terminal.

use std::collections::BTreeMap;

use quasar::{
    event::Outcome,
    policy::Decision,
    sink::{
        record::{Attributed, Body, Record},
        socket::Frame,
    },
    stats::{Counts, Snapshot},
    tui::{describe, severity, App, Entry, Severity},
};

fn record(source: &str, path: &str) -> Record {
    Record {
        time: "2026-09-09T00:00:00Z".to_owned(),
        source: source.to_owned(),
        attributed: Attributed::Named,
        container_id: None,
        pid: 42,
        ppid: 1,
        uid: 0,
        comm: "sh".to_owned(),
        body: Body::Exec {
            path: path.to_owned(),
            outcome: Outcome::Observed,
        },
    }
}

fn event(source: &str, path: &str, decision: Option<Decision>) -> Frame {
    Frame::Event {
        record: record(source, path),
        decision,
    }
}

fn snapshot(sources: &[(&str, u64, u64, u64)]) -> Frame {
    let mut by_source = BTreeMap::new();
    let mut total = Counts::default();

    for (name, execs, connects, alerts) in sources {
        by_source.insert(
            (*name).to_owned(),
            Counts {
                execs: *execs,
                connects: *connects,
                alerts: *alerts,
            },
        );
        total.execs += execs;
        total.connects += connects;
        total.alerts += alerts;
    }

    Frame::Stats {
        snapshot: Snapshot { total, by_source },
    }
}

fn paths(app: &App) -> Vec<String> {
    app.tail()
        .map(|entry| match entry {
            Entry::Event { record, .. } => match &record.body {
                Body::Exec { path, .. } => path.clone(),
                Body::Connect { dest, .. } => dest.to_string(),
            },
            Entry::Gap { missed } => format!("gap:{missed}"),
        })
        .collect()
}

/// A view that grows without limit is a memory leak wearing a user interface.
#[test]
fn the_tail_is_bounded_and_keeps_the_newest() {
    let mut app = App::new(3);

    for i in 0..10 {
        app.apply(event("api", &format!("/bin/{i}"), None));
    }

    assert_eq!(app.len(), 3);
    assert_eq!(paths(&app), ["/bin/7", "/bin/8", "/bin/9"]);
}

#[test]
fn a_zero_capacity_tail_still_does_not_grow() {
    let mut app = App::new(0);

    for i in 0..100 {
        app.apply(event("api", &format!("/bin/{i}"), None));
    }

    assert_eq!(app.len(), 1);
}

/// A live view with a silent hole is worse than one that admits the hole, so
/// the gap lands in the history where it happened as well as in the header.
#[test]
fn a_lag_frame_is_shown_in_place_and_counted() {
    let mut app = App::new(10);

    app.apply(event("api", "/bin/a", None));
    app.apply(Frame::Lagged { missed: 4_000 });
    app.apply(event("api", "/bin/b", None));
    app.apply(Frame::Lagged { missed: 6 });

    assert_eq!(app.missed, 4_006);
    assert_eq!(paths(&app), ["/bin/a", "gap:4000", "/bin/b", "gap:6"]);
}

#[test]
fn the_newest_entries_are_what_fits_on_screen() {
    let mut app = App::new(100);

    for i in 0..20 {
        app.apply(event("api", &format!("/bin/{i}"), None));
    }

    let visible: Vec<_> = app.recent(3).collect();
    assert_eq!(visible.len(), 3);
    assert!(matches!(
        visible[2],
        Entry::Event { record, .. }
            if record.body == Body::Exec {
                path: "/bin/19".to_owned(),
                outcome: Outcome::Observed,
            }
    ));
}

#[test]
fn asking_for_more_than_there_is_returns_everything() {
    let mut app = App::new(100);
    app.apply(event("api", "/bin/only", None));

    assert_eq!(app.recent(50).count(), 1);
}

#[test]
fn stats_replace_rather_than_accumulate() {
    let mut app = App::new(10);

    app.apply(snapshot(&[("api", 1, 0, 0)]));
    app.apply(snapshot(&[("api", 5, 2, 1)]));

    assert_eq!(app.snapshot.total.execs, 5);
    assert_eq!(app.snapshot.by_source["api"].connects, 2);
}

/// Busiest at the top, and stable between redraws -- a table that reshuffles
/// on every tick is unreadable.
#[test]
fn sources_are_busiest_first_and_ties_are_stable() {
    let mut app = App::new(10);
    app.apply(snapshot(&[
        ("quiet", 1, 0, 0),
        ("busy", 50, 50, 0),
        ("zulu", 10, 0, 0),
        ("alpha", 10, 0, 0),
        ("loud", 10, 0, 3),
    ]));

    let order: Vec<&str> = app.sources().into_iter().map(|(name, _)| name).collect();

    assert_eq!(order[0], "busy");
    // Same volume: the one with alerts outranks the quiet ones, then name.
    assert_eq!(&order[1..4], &["loud", "alpha", "zulu"]);
    assert_eq!(order[4], "quiet");
}

#[test]
fn a_denial_outranks_an_unbaselined_event() {
    assert_eq!(severity(Some(Decision::Denied)), Severity::Critical);
    assert_eq!(severity(Some(Decision::Unbaselined)), Severity::Warning);
    assert_eq!(severity(Some(Decision::Allowed)), Severity::Normal);
    assert_eq!(severity(None), Severity::Normal);

    assert!(Severity::Critical > Severity::Warning);
    assert!(Severity::Warning > Severity::Normal);
}

#[test]
fn events_describe_what_happened() {
    let exec = record("api", "/bin/sh");
    assert!(describe(&exec).contains("exec /bin/sh"));
    assert!(describe(&exec).contains("api"));

    let mut connect = record("api", "");
    connect.body = Body::Connect {
        proto: "tcp".to_owned(),
        dest: "9.9.9.9".parse().expect("addr"),
        port: 443,
    };
    assert!(describe(&connect).contains("connect tcp 9.9.9.9:443"));
}

/// A container name long enough to push the event off the line would make the
/// tail unreadable, so the name is what gets cut.
#[test]
fn a_long_source_is_truncated_not_the_event() {
    let long = record(&"a".repeat(80), "/bin/sh");
    let line = describe(&long);

    assert!(line.contains("exec /bin/sh"), "{line}");
    assert!(line.contains('…'), "{line}");
}
