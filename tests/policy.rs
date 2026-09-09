//! Policy precedence.
//!
//! The rule that makes a policy file trustworthy is that an automated pass
//! never overwrites a human one. If that breaks, a deliberate denial silently
//! reverts on the next `learn` run and nobody finds out until it matters.

use std::net::IpAddr;

use quasar::policy::{Decision, EgressRule, ExecRule, Policy, PolicySet, Source};

fn manual_exec(path: &str) -> ExecRule {
    ExecRule {
        path: path.to_owned(),
        source: Source::Manual,
        note: Some("entrypoint only".to_owned()),
    }
}

fn addr(s: &str) -> IpAddr {
    s.parse().expect("test address")
}

#[test]
fn deny_beats_allow() {
    let mut policy = Policy::default();
    policy.exec.allow.push(ExecRule {
        path: "/bin/sh".to_owned(),
        source: Source::Learned,
        note: None,
    });
    policy.exec.deny.push(manual_exec("/bin/sh"));

    assert_eq!(policy.check_exec("/bin/sh"), Decision::Denied);
}

#[test]
fn learning_does_not_re_add_a_manually_denied_path() {
    // The failure this guards: a human denies /bin/sh, the next learn run sees
    // /bin/sh execute, adds it as learned, and the denial is gone.
    let mut policy = Policy::default();
    policy.exec.deny.push(manual_exec("/bin/sh"));

    assert!(
        !policy.learn_exec("/bin/sh"),
        "learn must not add a denied path"
    );
    assert!(policy.exec.allow.is_empty());
    assert_eq!(policy.check_exec("/bin/sh"), Decision::Denied);
}

#[test]
fn learning_leaves_manual_entries_untouched() {
    let mut policy = Policy::default();
    policy.exec.allow.push(manual_exec("/bin/sh"));

    assert!(!policy.learn_exec("/bin/sh"), "already allowed");
    assert!(policy.learn_exec("/usr/bin/python3"));

    let manual = policy
        .exec
        .allow
        .iter()
        .find(|rule| rule.path == "/bin/sh")
        .expect("the manual entry survives");
    assert_eq!(manual.source, Source::Manual);
    assert_eq!(manual.note.as_deref(), Some("entrypoint only"));
}

#[test]
fn learning_an_unbaselined_path_adds_it_once() {
    let mut policy = Policy::default();

    assert!(policy.learn_exec("/usr/local/bin/gunicorn"));
    assert!(
        !policy.learn_exec("/usr/local/bin/gunicorn"),
        "no duplicate"
    );
    assert_eq!(policy.exec.allow.len(), 1);
    assert_eq!(policy.exec.allow[0].source, Source::Learned);
}

#[test]
fn a_broad_manual_cidr_absorbs_learned_host_routes() {
    // This is how a human generalising a range stops the file filling up with
    // one /32 per host.
    let mut policy = Policy::default();
    policy.egress.allow.push(EgressRule {
        cidr: "10.0.0.0/8".parse().expect("cidr"),
        source: Source::Manual,
        note: Some("LAN + tailscale".to_owned()),
    });

    assert!(!policy.learn_egress(addr("10.12.1.73")));
    assert!(!policy.learn_egress(addr("10.99.4.2")));
    assert_eq!(policy.egress.allow.len(), 1);

    // Something outside the range is still learned.
    assert!(policy.learn_egress(addr("93.184.215.14")));
    assert_eq!(policy.egress.allow.len(), 2);
}

#[test]
fn egress_decisions_respect_cidr_containment() {
    let mut policy = Policy::default();
    policy.egress.allow.push(EgressRule {
        cidr: "172.18.0.0/16".parse().expect("cidr"),
        source: Source::Manual,
        note: None,
    });
    policy.egress.deny.push(EgressRule {
        cidr: "172.18.5.0/24".parse().expect("cidr"),
        source: Source::Manual,
        note: None,
    });

    assert_eq!(policy.check_egress(addr("172.18.1.1")), Decision::Allowed);
    // A narrower deny inside a broader allow still wins.
    assert_eq!(policy.check_egress(addr("172.18.5.9")), Decision::Denied);
    assert_eq!(policy.check_egress(addr("8.8.8.8")), Decision::Unbaselined);
}

#[test]
fn v6_destinations_are_expressible() {
    // Phase 3 captures v6, so policy has to be able to talk about it.
    let mut policy = Policy::default();
    policy.egress.allow.push(EgressRule {
        cidr: "2606:4700::/32".parse().expect("cidr"),
        source: Source::Manual,
        note: None,
    });

    assert_eq!(
        policy.check_egress(addr("2606:4700:4700::1111")),
        Decision::Allowed
    );
    assert!(policy.learn_egress(addr("2001:db8::1")));
    assert_eq!(policy.egress.allow[1].cidr.prefix_len(), 128);
}

#[test]
fn round_trips_through_toml() {
    let dir = tempdir();
    let mut set = PolicySet::default();
    let policy = set.entry("marist-backend");
    policy.meta.image = Some("infra-marist-backend".to_owned());
    policy.exec.allow.push(manual_exec("/bin/sh"));
    policy.learn_exec("/usr/local/bin/python3.12");
    policy.learn_egress(addr("172.18.0.5"));

    set.save_dir(&dir).expect("save");
    let reloaded = PolicySet::load_dir(&dir).expect("load");

    assert_eq!(
        reloaded.by_container.get("marist-backend"),
        set.by_container.get("marist-backend")
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_missing_policy_directory_is_empty_not_an_error() {
    // The service must start cleanly with no policy at all, so a bad or absent
    // policy file can never prevent startup.
    let set = PolicySet::load_dir(std::path::Path::new("/nonexistent/quasar/policy"))
        .expect("a missing directory is not an error");
    assert!(set.by_container.is_empty());
}

#[test]
fn entries_are_sorted_on_save_so_diffs_stay_readable() {
    let dir = tempdir();
    let mut set = PolicySet::default();
    let policy = set.entry("demo");
    for path in ["/usr/bin/zsh", "/bin/cat", "/usr/bin/env"] {
        policy.learn_exec(path);
    }
    set.save_dir(&dir).expect("save");

    let text = std::fs::read_to_string(dir.join("demo.toml")).expect("read");
    let order: Vec<_> = text
        .match_indices("path = ")
        .map(|(i, _)| text[i..].lines().next().unwrap_or_default().to_owned())
        .collect();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(
        order, sorted,
        "policy entries must be written in sorted order"
    );

    std::fs::remove_dir_all(&dir).ok();
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "quasar-policy-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn unstable_proc_paths_are_not_baselined() {
    // runc re-execs through /proc/self/fd/<n> on every container start. The
    // descriptor number varies, so learning it produces a rule that never
    // matches again and grows a new dead entry each time.
    let dir = tempdir();
    let log = dir.join("unstable.jsonl");
    std::fs::write(
        &log,
        concat!(
            r#"{"time":"2026-09-09T06:40:07Z","source":"demo","attributed":"named","pid":1,"ppid":1,"uid":0,"comm":"6","kind":"exec","path":"/proc/self/fd/6"}"#,
            "\n",
            r#"{"time":"2026-09-09T06:40:08Z","source":"demo","attributed":"named","pid":2,"ppid":1,"uid":0,"comm":"sh","kind":"exec","path":"/bin/sh"}"#,
            "\n",
        ),
    )
    .expect("write log");

    let observations = quasar::policy::learn::observe(&log).expect("observe");
    assert_eq!(observations.unstable_paths, 1);

    let out = dir.join("policy");
    quasar::policy::learn::merge_into(&observations, &out).expect("merge");

    let text = std::fs::read_to_string(out.join("demo.toml")).expect("read");
    assert!(text.contains("/bin/sh"), "real paths are still learned");
    assert!(
        !text.contains("/proc/self/fd"),
        "an unmatchable path must never reach the policy file"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// -- what gets alerted on ---------------------------------------------------

fn policy_set(container: &str, policy: Policy) -> PolicySet {
    let mut set = PolicySet::default();
    set.by_container.insert(container.to_owned(), policy);
    set
}

fn allowing(path: &str) -> Policy {
    let mut policy = Policy::default();
    policy.exec.allow.push(ExecRule {
        path: path.to_owned(),
        source: Source::Learned,
        note: None,
    });
    policy
}

#[test]
fn an_unbaselined_exec_alerts() {
    let set = policy_set("api", allowing("/bin/sh"));

    assert_eq!(
        set.exec_alert("api", "/bin/nc"),
        Some(Decision::Unbaselined)
    );
}

#[test]
fn a_denied_exec_alerts() {
    let mut policy = allowing("/bin/sh");
    policy.exec.deny.push(manual_exec("/bin/nc"));

    assert_eq!(
        policy_set("api", policy).exec_alert("api", "/bin/nc"),
        Some(Decision::Denied)
    );
}

#[test]
fn an_allowed_exec_is_silent() {
    let set = policy_set("api", allowing("/bin/sh"));

    assert_eq!(set.exec_alert("api", "/bin/sh"), None);
}

/// The service must start cleanly with no policy at all. A container nobody has
/// baselined yet is observed and logged, never alerted on -- otherwise adding a
/// container to the host pages whoever is on call.
#[test]
fn a_container_with_no_policy_never_alerts() {
    let set = policy_set("api", allowing("/bin/sh"));

    assert_eq!(set.exec_alert("unknown-container", "/bin/nc"), None);
    assert_eq!(set.egress_alert("unknown-container", addr("9.9.9.9")), None);
}

/// runc copies itself into a memfd and execs the descriptor, so container init
/// shows up as /proc/self/fd/N on every `docker exec`. Alerting on it would
/// make every container start a false positive.
#[test]
fn the_runtime_reexec_does_not_alert() {
    let set = policy_set("api", allowing("/bin/sh"));

    assert_eq!(set.exec_alert("api", "/proc/self/fd/6"), None);
    assert_eq!(set.exec_alert("api", "/proc/self/fd/14"), None);
}

/// The exemption is exactly `/proc/self/fd/<digits>`. Anything else under
/// /proc is a path an attacker chose, and stays loud.
#[test]
fn other_proc_paths_still_alert() {
    let set = policy_set("api", allowing("/bin/sh"));

    for path in [
        "/proc/self/fd/6/../../../bin/nc",
        "/proc/self/fdx/6",
        "/proc/self/fd/",
        "/proc/self/fd/6a",
        "/proc/1234/fd/6",
        "/proc/self/exe",
    ] {
        assert_eq!(
            set.exec_alert("api", path),
            Some(Decision::Unbaselined),
            "{path} should still alert"
        );
    }
}

/// Exempt from *alerting* only. It must never become an allow rule: the fd
/// number is a slot an attacker controls, so allowing it would allow every
/// future exec through that slot.
#[test]
fn the_runtime_reexec_is_still_not_baselined() {
    let mut policy = Policy::default();

    assert!(!policy.learn_exec("/proc/self/fd/6"));
    assert!(policy.exec.allow.is_empty());
}

#[test]
fn unbaselined_egress_alerts_and_allowed_egress_does_not() {
    let mut policy = Policy::default();
    policy.egress.allow.push(EgressRule {
        cidr: "10.0.0.0/8".parse().expect("test cidr"),
        source: Source::Manual,
        note: None,
    });
    let set = policy_set("api", policy);

    assert_eq!(set.egress_alert("api", addr("10.1.2.3")), None);
    assert_eq!(
        set.egress_alert("api", addr("9.9.9.9")),
        Some(Decision::Unbaselined)
    );
}

// -- the allowlist key ------------------------------------------------------
//
// The probe reads the path into a buffer of exactly this size and looks the
// result up byte for byte. A key built differently here never matches, which
// under observation means the filter does nothing and under enforcement means
// everything is blocked.

use quasar::{event::QUASAR_FILENAME_LEN, policy::sync::exec_key_for};

#[test]
fn a_key_is_the_path_then_nul_then_zeros() {
    let key = exec_key_for(7, "/bin/sh").expect("a short path fits");

    assert_eq!(key.cgroup_id, 7);
    assert_eq!(&key.path[..7], b"/bin/sh");
    assert_eq!(
        key.path[7], 0,
        "the probe hashes nothing -- it reads a string"
    );
    assert!(
        key.path[8..].iter().all(|&b| b == 0),
        "the tail must be zeroed or the same path yields two different keys"
    );
}

#[test]
fn the_longest_path_that_fits_still_fits() {
    let longest = "/".repeat(QUASAR_FILENAME_LEN as usize - 1);
    let key = exec_key_for(1, &longest).expect("255 bytes plus a NUL is exactly the buffer");

    assert_eq!(key.path[QUASAR_FILENAME_LEN as usize - 1], 0);
}

/// A truncated path is a prefix, and a prefix can name a different binary.
/// Refusing is the only safe answer once a match means permission to execute.
#[test]
fn a_path_too_long_for_the_key_is_refused_not_truncated() {
    let too_long = "/".repeat(QUASAR_FILENAME_LEN as usize);

    assert!(exec_key_for(1, &too_long).is_none());
    assert!(exec_key_for(1, &"x".repeat(4096)).is_none());
}

#[test]
fn different_containers_never_share_a_key() {
    assert_ne!(
        exec_key_for(1, "/bin/sh").expect("key").cgroup_id,
        exec_key_for(2, "/bin/sh").expect("key").cgroup_id
    );
}
