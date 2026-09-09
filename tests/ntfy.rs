use std::time::{Duration, Instant};

use quasar::{
    policy::Decision,
    sink::ntfy::{render, Admit, Alert, AlertKey, Suppressor},
};

const WINDOW: Duration = Duration::from_secs(300);

fn key(container: &str, decision: Decision, subject: &str) -> AlertKey {
    AlertKey {
        container: container.to_owned(),
        decision,
        subject: subject.to_owned(),
    }
}

fn alert(k: AlertKey) -> Alert {
    Alert {
        key: k,
        detail: "pid 1 ppid 0 uid 0 comm sh".to_owned(),
    }
}

#[test]
fn the_first_alert_always_goes_out() {
    let mut s = Suppressor::new(WINDOW);
    let k = key("api", Decision::Unbaselined, "exec /bin/sh");

    assert_eq!(s.admit(&k, Instant::now()), Admit::Send { suppressed: 0 });
}

#[test]
fn repeats_within_the_window_are_held() {
    let mut s = Suppressor::new(WINDOW);
    let k = key("api", Decision::Unbaselined, "exec /bin/sh");
    let now = Instant::now();

    s.admit(&k, now);
    for i in 1..50 {
        assert_eq!(s.admit(&k, now + Duration::from_secs(i)), Admit::Hold);
    }
}

#[test]
fn a_different_subject_is_a_different_alert() {
    let mut s = Suppressor::new(WINDOW);
    let now = Instant::now();

    s.admit(&key("api", Decision::Unbaselined, "exec /bin/sh"), now);
    assert_eq!(
        s.admit(&key("api", Decision::Unbaselined, "exec /bin/nc"), now),
        Admit::Send { suppressed: 0 }
    );
    assert_eq!(
        s.admit(&key("db", Decision::Unbaselined, "exec /bin/sh"), now),
        Admit::Send { suppressed: 0 }
    );
}

/// Denied and unbaselined mean different things and read differently, so one
/// must never silence the other.
#[test]
fn a_denial_is_not_suppressed_by_an_unbaselined_alert() {
    let mut s = Suppressor::new(WINDOW);
    let now = Instant::now();

    s.admit(&key("api", Decision::Unbaselined, "exec /bin/sh"), now);
    assert_eq!(
        s.admit(&key("api", Decision::Denied, "exec /bin/sh"), now),
        Admit::Send { suppressed: 0 }
    );
}

#[test]
fn the_next_alert_after_the_window_reports_what_was_held() {
    let mut s = Suppressor::new(WINDOW);
    let k = key("api", Decision::Unbaselined, "exec /bin/sh");
    let now = Instant::now();

    s.admit(&k, now);
    for i in 1..=9 {
        s.admit(&k, now + Duration::from_secs(i));
    }

    assert_eq!(s.admit(&k, now + WINDOW), Admit::Send { suppressed: 9 });
    // The count resets, rather than being reported again.
    assert_eq!(s.admit(&k, now + WINDOW * 2), Admit::Send { suppressed: 0 });
}

/// A burst that stops must still be reported in full. Otherwise you are told
/// an alert fired once and never told it fired ten thousand more times.
#[test]
fn a_burst_that_stops_is_still_summarised() {
    let mut s = Suppressor::new(WINDOW);
    let k = key("api", Decision::Unbaselined, "exec /bin/sh");
    let now = Instant::now();

    s.admit(&k, now);
    for i in 1..=10_000 {
        s.admit(&k, now + Duration::from_millis(i));
    }

    assert_eq!(s.expired(now + WINDOW), vec![(k, 10_000)]);
}

#[test]
fn a_quiet_alert_is_forgotten_rather_than_summarised() {
    let mut s = Suppressor::new(WINDOW);
    let k = key("api", Decision::Unbaselined, "exec /bin/sh");
    let now = Instant::now();

    s.admit(&k, now);

    assert!(s.expired(now + WINDOW).is_empty());
    // Forgotten, so the next occurrence is a fresh alert rather than a repeat.
    assert_eq!(s.admit(&k, now + WINDOW * 2), Admit::Send { suppressed: 0 });
}

#[test]
fn a_denial_outranks_an_unbaselined_alert() {
    let denied = render(&key("api", Decision::Denied, "exec /bin/nc"), "pid 7", 0);
    let unbaselined = render(
        &key("api", Decision::Unbaselined, "exec /bin/nc"),
        "pid 7",
        0,
    );

    assert_eq!(denied.priority, "high");
    assert_eq!(unbaselined.priority, "default");
    assert!(denied.body.starts_with("denied "));
    assert!(unbaselined.body.starts_with("unbaselined "));
}

#[test]
fn the_message_names_the_container_and_what_happened() {
    let m = render(
        &key("marist-backend", Decision::Unbaselined, "exec /bin/sh"),
        "pid 42 ppid 1 uid 0 comm sh",
        0,
    );

    assert_eq!(m.title, "quasar: marist-backend");
    assert_eq!(
        m.body,
        "unbaselined exec /bin/sh\npid 42 ppid 1 uid 0 comm sh"
    );
}

#[test]
fn a_held_back_count_reaches_the_reader() {
    let m = alert(key("api", Decision::Unbaselined, "exec /bin/sh")).render(41);

    assert!(
        m.body.ends_with("+41 more since the last alert"),
        "body was {:?}",
        m.body
    );
}

/// A window summary has no single event behind it, so it carries a count and
/// no pid -- and must not leave a dangling blank line where the detail was.
#[test]
fn a_summary_carries_no_detail() {
    let m = render(&key("api", Decision::Unbaselined, "exec /bin/sh"), "", 500);

    assert_eq!(
        m.body,
        "unbaselined exec /bin/sh\n+500 more since the last alert"
    );
}

/// The one thing the unit tests above cannot see: what actually goes on the
/// wire. ntfy reads the title, priority and tags from headers, so a rename or
/// a typo there is silent -- the POST succeeds and the notification is wrong.
#[tokio::test]
async fn the_post_carries_the_ntfy_headers() {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");

        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n")
                && request.ends_with(b"since the last alert")
            {
                break;
            }
        }

        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .expect("respond");
        String::from_utf8_lossy(&request).into_owned()
    });

    quasar::sink::ntfy::NtfySink::new(&format!("http://{addr}/quasar-test"))
        .expect("sink")
        .send(&render(
            &key("api", Decision::Denied, "exec /bin/nc"),
            "pid 42 ppid 1 uid 0 comm nc",
            3,
        ))
        .await
        .expect("send");

    let request = served.join().expect("server thread").to_lowercase();

    assert!(request.starts_with("post /quasar-test "), "{request}");
    assert!(request.contains("\r\ntitle: quasar: api\r\n"), "{request}");
    assert!(request.contains("\r\npriority: high\r\n"), "{request}");
    assert!(
        request.contains("\r\ntags: rotating_light\r\n"),
        "{request}"
    );
    assert!(
        request.ends_with(
            "denied exec /bin/nc\npid 42 ppid 1 uid 0 comm nc\n+3 more since the last alert"
        ),
        "{request}"
    );
}
