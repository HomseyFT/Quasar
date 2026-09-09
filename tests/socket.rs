//! The property phase 5 is accepted on: clients cannot affect the daemon.

use std::{
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

use quasar::{
    policy::Decision,
    sink::{
        record::{Attributed, Body, Record},
        socket::{serve, Client, Frame},
    },
    stats::Snapshot,
};

fn socket_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("quasar-test-{}-{}.sock", std::process::id(), name));
    let _ = std::fs::remove_file(&path);
    path
}

fn record(source: &str, path: &str) -> Record {
    Record {
        time: "2026-09-09T00:00:00Z".to_owned(),
        source: source.to_owned(),
        attributed: Attributed::Named,
        container_id: Some("deadbeef".to_owned()),
        pid: 42,
        ppid: 1,
        uid: 0,
        comm: "sh".to_owned(),
        body: Body::Exec {
            path: path.to_owned(),
        },
    }
}

async fn next(client: &mut Client) -> Option<Frame> {
    tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .expect("timed out waiting for a frame")
        .expect("frame error")
}

/// Connect, and wait until the daemon has actually subscribed us.
///
/// `Client::connect` returns as soon as the client side is connected, which
/// can be before the server has accepted and subscribed it -- and a broadcast
/// only reaches receivers that already exist. The immediate snapshot is sent
/// from the serving task, so receiving it proves the subscription is live.
async fn attach(path: &std::path::Path) -> Client {
    let mut client = Client::connect(path).await.expect("connect");
    assert!(
        matches!(next(&mut client).await, Some(Frame::Stats { .. })),
        "the first frame should be the immediate snapshot"
    );
    client
}

/// Skip stats frames, which arrive on a timer and are not what a given test
/// is asking about.
async fn next_event(client: &mut Client) -> Option<Record> {
    for _ in 0..8 {
        match next(client).await? {
            Frame::Event { record, .. } => return Some(record),
            _ => continue,
        }
    }
    None
}

#[test]
fn frames_round_trip() {
    let frames = [
        Frame::Event {
            record: record("api", "/bin/sh"),
            decision: Some(Decision::Denied),
        },
        Frame::Stats {
            snapshot: Snapshot::default(),
        },
        Frame::Lagged { missed: 17 },
    ];

    for frame in frames {
        let line = serde_json::to_string(&frame).expect("serialise");
        assert!(!line.contains('\n'), "a frame must fit on one line: {line}");
        let back: Frame = serde_json::from_str(&line).expect("deserialise");
        assert_eq!(frame, back);
    }
}

/// A connect record round trips too -- the body is flattened, so a second
/// variant is a real risk of the framing colliding with the record's own tag.
#[test]
fn a_connect_frame_round_trips() {
    let mut r = record("api", "");
    r.body = Body::Connect {
        proto: "tcp".to_owned(),
        dest: "9.9.9.9".parse::<IpAddr>().expect("addr"),
        port: 443,
    };
    let frame = Frame::Event {
        record: r,
        decision: Some(Decision::Unbaselined),
    };

    let line = serde_json::to_string(&frame).expect("serialise");
    assert_eq!(
        serde_json::from_str::<Frame>(&line).expect("deserialise"),
        frame
    );
}

#[tokio::test]
async fn a_client_sees_events_and_an_immediate_snapshot() {
    let path = socket_path("basic");
    let publisher = serve(&path).expect("serve");
    // attach asserts the immediate snapshot, which is the point here: a client
    // that just attached shows real numbers rather than a blank screen.
    let mut client = attach(&path).await;

    publisher.publish(&record("api", "/bin/sh"), None);

    let got = next_event(&mut client).await.expect("an event");
    assert_eq!(got.source, "api");
    assert_eq!(
        got.body,
        Body::Exec {
            path: "/bin/sh".to_owned()
        }
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn counters_track_what_was_published() {
    let path = socket_path("counters");
    let publisher = serve(&path).expect("serve");
    let mut client = attach(&path).await;

    publisher.publish(&record("api", "/bin/sh"), None);
    publisher.publish(&record("api", "/bin/nc"), Some(Decision::Unbaselined));
    publisher.publish(&record("db", "/bin/sh"), None);

    let mut seen = None;
    for _ in 0..64 {
        if let Some(Frame::Stats { snapshot }) = next(&mut client).await {
            if snapshot.total.execs == 3 {
                seen = Some(snapshot);
                break;
            }
        }
    }

    let snapshot = seen.expect("a snapshot counting all three");
    assert_eq!(snapshot.total.execs, 3);
    assert_eq!(snapshot.total.alerts, 1);
    assert_eq!(snapshot.by_source["api"].execs, 2);
    assert_eq!(snapshot.by_source["api"].alerts, 1);
    assert_eq!(snapshot.by_source["db"].execs, 1);

    let _ = std::fs::remove_file(&path);
}

/// The acceptance criterion. A client that stops reading must lose its own
/// frames and be told the size of the gap -- never slow the publisher down.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_reading_loses_its_own_frames() {
    let path = socket_path("lagging");
    let publisher = serve(&path).expect("serve");
    let mut client = attach(&path).await;

    // Far more than the broadcast backlog, and more than a socket buffer
    // holds, so the client's queue must overflow.
    let started = Instant::now();
    for i in 0..20_000 {
        publisher.publish(&record("api", &format!("/bin/{i}")), None);
    }
    let publishing = started.elapsed();

    assert!(
        publishing < Duration::from_secs(2),
        "publishing to a stalled client took {publishing:?} -- it applied back pressure"
    );

    let mut lagged = None;
    for _ in 0..5_000 {
        match next(&mut client).await {
            Some(Frame::Lagged { missed }) => {
                lagged = Some(missed);
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }

    assert!(
        lagged.is_some_and(|missed| missed > 0),
        "the client was never told it had fallen behind"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_dead_client_does_not_disturb_the_next_one() {
    let path = socket_path("dead");
    let publisher = serve(&path).expect("serve");

    let client = Client::connect(&path).await.expect("connect");
    drop(client);
    for i in 0..100 {
        publisher.publish(&record("api", &format!("/bin/{i}")), None);
    }

    let mut fresh = attach(&path).await;
    publisher.publish(&record("api", "/bin/after"), None);

    let got = next_event(&mut fresh).await.expect("an event");
    assert_eq!(
        got.body,
        Body::Exec {
            path: "/bin/after".to_owned()
        }
    );

    let _ = std::fs::remove_file(&path);
}

/// The headless case, which is the normal one.
#[tokio::test]
async fn publishing_with_no_client_attached_is_fine() {
    let path = socket_path("headless");
    let publisher = serve(&path).expect("serve");

    for i in 0..10_000 {
        publisher.publish(&record("api", &format!("/bin/{i}")), None);
    }

    let mut client = attach(&path).await;
    publisher.publish(&record("api", "/bin/late"), None);
    assert!(next_event(&mut client).await.is_some());

    let _ = std::fs::remove_file(&path);
}

/// This stream is every exec and every destination on the host. Nothing but
/// its owner reads it.
#[tokio::test]
async fn the_socket_is_not_readable_by_others() {
    let path = socket_path("perms");
    let _publisher = serve(&path).expect("serve");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);

    let _ = std::fs::remove_file(&path);
}

/// A crashed run leaves the socket file behind, and bind would fail on it.
#[tokio::test]
async fn a_stale_socket_file_is_replaced() {
    let path = socket_path("stale");
    let first = serve(&path).expect("serve");
    drop(first);

    let publisher = serve(&path).expect("serve over the stale socket");
    let mut client = attach(&path).await;
    publisher.publish(&record("api", "/bin/sh"), None);
    assert!(next_event(&mut client).await.is_some());

    let _ = std::fs::remove_file(&path);
}

/// Removing a stale socket is safe. Removing whatever else happens to be at
/// that path is not.
#[tokio::test]
async fn a_regular_file_is_never_deleted() {
    let path = socket_path("regular");
    std::fs::write(&path, b"not a socket").expect("write");

    assert!(serve(&path).is_err());
    assert_eq!(
        std::fs::read(&path).expect("still there"),
        b"not a socket",
        "serve deleted a file that was not a socket"
    );

    let _ = std::fs::remove_file(&path);
}
