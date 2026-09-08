//! Attribution parsing. These run without root and without a Docker daemon:
//! the parsing is where the driver-specific knowledge lives, and it is what
//! silently mis-attributes every event if it is wrong.

use quasar::registry::{container_id_from_cgroup_path, Attribution};

const ID: &str = "3f9a1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";

#[test]
fn parses_the_systemd_driver_layout() {
    let path = format!("/sys/fs/cgroup/system.slice/docker-{ID}.scope");
    assert_eq!(container_id_from_cgroup_path(&path), Some(ID));
}

#[test]
fn parses_the_cgroupfs_driver_layout() {
    let path = format!("/sys/fs/cgroup/docker/{ID}");
    assert_eq!(container_id_from_cgroup_path(&path), Some(ID));
}

#[test]
fn parses_a_proc_cgroup_line() {
    // Fallback 2 reads /proc/<pid>/cgroup, whose v2 lines carry a `0::` prefix.
    let line = format!("0::/system.slice/docker-{ID}.scope");
    assert_eq!(container_id_from_cgroup_path(&line), Some(ID));
}

#[test]
fn ignores_paths_that_are_not_containers() {
    for path in [
        "/sys/fs/cgroup/system.slice/sshd.service",
        "/sys/fs/cgroup/user.slice/user-1000.slice",
        "/",
        "",
        // A systemd-style name whose payload is not a container id.
        "/sys/fs/cgroup/system.slice/docker-nonsense.scope",
        // Right length, but not hex.
        "/sys/fs/cgroup/docker/zzzz1b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    ] {
        assert_eq!(container_id_from_cgroup_path(path), None, "path: {path}");
    }
}

#[test]
fn rejects_a_truncated_id() {
    let path = format!("/sys/fs/cgroup/docker/{}", &ID[..12]);
    assert_eq!(container_id_from_cgroup_path(&path), None);
}

#[test]
fn display_degrades_through_the_fallback_chain() {
    let named = Attribution::Named {
        id: ID.to_owned(),
        name: "marist-backend".to_owned(),
    };
    let id_only = Attribution::Container { id: ID.to_owned() };
    let unknown = Attribution::Unattributed { cgroup_id: 53853 };

    assert_eq!(named.to_string(), "marist-backend");
    assert_eq!(id_only.to_string(), "docker:3f9a1b2c4d5e");
    assert_eq!(unknown.to_string(), "cgroup:53853");

    // An event is never dropped for lack of a name, but it is marked.
    assert!(named.is_attributed());
    assert!(id_only.is_attributed());
    assert!(!unknown.is_attributed());
}
