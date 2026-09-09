//! Attribution parsing. These run without root and without a Docker daemon:
//! the parsing is where the driver-specific knowledge lives, and it is what
//! silently mis-attributes every event if it is wrong.

use quasar::registry::{classify_cgroup_path, container_id_from_cgroup_path, Attribution};

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
fn classifies_a_container_cgroup() {
    let path = format!("system.slice/docker-{ID}.scope");
    assert_eq!(
        classify_cgroup_path(&path),
        Attribution::Container { id: ID.to_owned() }
    );
}

#[test]
fn classifies_a_host_cgroup() {
    // Positive evidence of a host process: the cgroup exists and names a unit.
    assert_eq!(
        classify_cgroup_path("/system.slice/firewalld.service"),
        Attribution::Host {
            path: "system.slice/firewalld.service".to_owned()
        }
    );
}

#[test]
fn host_is_not_the_same_claim_as_unknown() {
    // Both are "not a container", but only one is an attribution failure.
    let host = classify_cgroup_path("system.slice/containerd.service");
    let unknown = Attribution::Unknown { cgroup_id: 57404 };

    assert!(!host.is_container() && !unknown.is_container());
    assert!(!host.is_unknown(), "a located host cgroup is not a failure");
    assert!(unknown.is_unknown());
    assert_ne!(host, unknown);
}

#[test]
fn display_degrades_through_the_fallback_chain() {
    let named = Attribution::Named {
        id: ID.to_owned(),
        name: "marist-backend".to_owned(),
    };
    let id_only = Attribution::Container { id: ID.to_owned() };
    let host = Attribution::Host {
        path: "system.slice/firewalld.service".to_owned(),
    };
    let unknown = Attribution::Unknown { cgroup_id: 53853 };

    assert_eq!(named.to_string(), "marist-backend");
    assert_eq!(id_only.to_string(), "docker:3f9a1b2c4d5e");
    assert_eq!(host.to_string(), "host:system.slice/firewalld.service");
    assert_eq!(unknown.to_string(), "cgroup:53853");

    // An event is never dropped for lack of a name, but a real failure is marked.
    assert!(named.is_container());
    assert!(id_only.is_container());
    assert!(!host.is_container());
    assert!(!unknown.is_container());
}
