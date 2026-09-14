//! The rails, as far as they can be tested without a kernel.

use std::time::Duration;

use quasar::{
    enforce::{lease_from, parse_duration, requests, Mode, LEASE, RENEW},
    policy::{ExecRule, Policy, Source},
};

#[test]
fn a_lease_outlives_the_heartbeat_that_renews_it() {
    // If the lease were not comfortably longer than the renewal interval, one
    // late tick would disarm enforcement by accident.
    assert!(
        LEASE > RENEW * 2,
        "a lease of {LEASE:?} against a {RENEW:?} heartbeat is too tight"
    );
}

#[test]
fn a_lease_is_in_the_future_and_cannot_overflow() {
    let now = 1_000_000_000;
    assert_eq!(lease_from(now), now + LEASE.as_nanos() as u64);
    assert_eq!(
        lease_from(u64::MAX),
        u64::MAX,
        "saturates rather than wraps"
    );
}

#[test]
fn durations_parse() {
    assert_eq!(parse_duration("45s").expect("45s"), Duration::from_secs(45));
    assert_eq!(
        parse_duration("15m").expect("15m"),
        Duration::from_secs(900)
    );
    assert_eq!(parse_duration("2h").expect("2h"), Duration::from_secs(7200));
    assert_eq!(
        parse_duration("7d").expect("7d"),
        Duration::from_secs(604_800)
    );
    // A bare number is seconds, which is what anyone typing one means.
    assert_eq!(parse_duration("90").expect("90"), Duration::from_secs(90));
    assert_eq!(
        parse_duration("  30s  ").expect("padded"),
        Duration::from_secs(30)
    );
}

#[test]
fn nonsense_durations_are_refused_rather_than_guessed_at() {
    for bad in ["", "s", "later", "-5s", "5 years", "1w", "3.5h"] {
        assert!(
            parse_duration(bad).is_err(),
            "{bad:?} should not parse to a duration"
        );
    }
}

#[test]
fn an_overlong_duration_is_an_error_not_a_wrap() {
    assert!(parse_duration(&format!("{}d", u64::MAX)).is_err());
}

#[test]
fn dry_run_and_enforce_are_collected_by_name() {
    let asked = requests(
        &["watcher".to_owned()],
        &["victim".to_owned(), "other".to_owned()],
    )
    .expect("requests");

    assert_eq!(asked["watcher"], Mode::DryRun);
    assert_eq!(asked["victim"], Mode::Enforce);
    assert_eq!(asked.len(), 3);
}

/// Asking for both is a contradiction, and silently picking one would mean
/// enforcing something the operator may have thought was only being watched.
#[test]
fn a_container_cannot_be_both_watched_and_enforced() {
    assert!(requests(&["api".to_owned()], &["api".to_owned()]).is_err());
}

/// An empty allowlist under enforcement means the container can execute
/// nothing at all.
#[test]
fn a_policy_that_allows_nothing_cannot_govern() {
    let mut policy = Policy::default();
    assert!(!policy.can_govern());

    policy.exec.allow.push(ExecRule {
        path: "/bin/sh".to_owned(),
        source: Source::Learned,
        note: None,
    });
    assert!(policy.can_govern());
}
