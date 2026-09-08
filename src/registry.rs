//! cgroup id -> container name.
//!
//! The chain from a kernel event to a name a human recognises:
//!
//! `bpf_get_current_cgroup_id()` returns the cgroup directory's inode number.
//! Walking `/sys/fs/cgroup` and stat()ing each directory finds the one with
//! that inode. The directory name carries the 64-hex Docker container id --
//! under the systemd driver as `docker-<id>.scope`, under the cgroupfs driver
//! as a bare `<id>` beneath `docker/`. The Docker API turns that id into a name.
//!
//! Three fallbacks, in order, because the race is real: a container can exec
//! before userspace has learned it exists, and a short-lived container's cgroup
//! is gone before the lookup runs.
//!
//!   1. Cache hit.
//!   2. `/proc/<pid>/cgroup`, if the process still exists.
//!   3. `cgroup:<id>`, marked unattributed.
//!
//! An event is never dropped for lack of a name. An unattributed exec is still
//! a signal, and it is the interesting one if something is deliberately
//! short-lived.

use std::{
    collections::HashMap,
    fmt, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use bollard::{
    query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder},
    Docker, API_DEFAULT_VERSION,
};
use futures_util::StreamExt;
use tokio::sync::RwLock;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTAINER_ID_LEN: usize = 64;
const SHORT_ID_LEN: usize = 12;
const DOCKER_TIMEOUT_SECS: u64 = 20;

/// Who caused an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// Both the container and its name are known.
    Named { id: String, name: String },
    /// The cgroup belongs to a container whose name is not known yet. Reached
    /// when an exec races the Docker event stream.
    Container { id: String },
    /// No container could be determined.
    Unattributed { cgroup_id: u64 },
}

impl Attribution {
    pub fn is_attributed(&self) -> bool {
        !matches!(self, Self::Unattributed { .. })
    }

    pub fn container_id(&self) -> Option<&str> {
        match self {
            Self::Named { id, .. } | Self::Container { id } => Some(id),
            Self::Unattributed { .. } => None,
        }
    }
}

impl fmt::Display for Attribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named { name, .. } => write!(f, "{name}"),
            Self::Container { id } => write!(f, "docker:{}", short(id)),
            Self::Unattributed { cgroup_id } => write!(f, "cgroup:{cgroup_id}"),
        }
    }
}

fn short(id: &str) -> &str {
    &id[..SHORT_ID_LEN.min(id.len())]
}

/// Extract the 64-hex Docker container id from a cgroup path.
///
/// Handles both Docker cgroup drivers, and the `/proc/<pid>/cgroup` line format,
/// by scanning path components rather than assuming a layout:
///
/// ```text
/// systemd   /system.slice/docker-3f9a...b1.scope
/// cgroupfs  /docker/3f9a...b1
/// proc      0::/system.slice/docker-3f9a...b1.scope
/// ```
pub fn container_id_from_cgroup_path(path: &str) -> Option<&str> {
    path.split('/').find_map(container_id_from_component)
}

fn container_id_from_component(component: &str) -> Option<&str> {
    let candidate = match component.strip_prefix("docker-") {
        Some(rest) => rest.strip_suffix(".scope")?,
        None => component,
    };
    is_container_id(candidate).then_some(candidate)
}

fn is_container_id(s: &str) -> bool {
    s.len() == CONTAINER_ID_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Find the cgroup directory whose inode number is `ino`.
fn find_cgroup_by_ino(root: &Path, ino: u64) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.ino() == ino {
                return Some(entry.path());
            }
            stack.push(entry.path());
        }
    }
    None
}

/// Fallback 2: ask the process itself, if it is still alive.
fn container_id_from_proc(pid: u32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    text.lines()
        .find_map(|line| container_id_from_cgroup_path(line).map(str::to_owned))
}

#[derive(Default)]
struct State {
    /// Fully resolved attributions, keyed by cgroup inode.
    by_cgroup: HashMap<u64, Attribution>,
    /// Container id -> name.
    names: HashMap<String, String>,
}

pub struct Registry {
    /// `None` when the Docker API was unreachable at startup. The registry
    /// still resolves cgroup ids to container ids; it just cannot name them.
    docker: Option<Docker>,
    cgroup_root: PathBuf,
    state: RwLock<State>,
}

impl Registry {
    pub async fn connect(endpoint: Option<&str>) -> Result<Self> {
        let docker = match endpoint {
            None => Docker::connect_with_unix_defaults(),
            Some(url) if url.starts_with("unix://") || url.starts_with('/') => {
                Docker::connect_with_unix(url, DOCKER_TIMEOUT_SECS, API_DEFAULT_VERSION)
            }
            Some(url) => Docker::connect_with_http(url, DOCKER_TIMEOUT_SECS, API_DEFAULT_VERSION),
        }
        .context("connecting to the Docker API")?;

        let registry = Self {
            docker: Some(docker),
            cgroup_root: PathBuf::from(CGROUP_ROOT),
            state: RwLock::default(),
        };
        registry
            .refresh_names()
            .await
            .context("listing containers")?;

        Ok(registry)
    }

    /// A registry with no Docker connection. Events still resolve as far as a
    /// container id, so the monitor keeps working when the daemon does not.
    pub fn offline() -> Self {
        Self {
            docker: None,
            cgroup_root: PathBuf::from(CGROUP_ROOT),
            state: RwLock::default(),
        }
    }

    pub async fn resolve(&self, cgroup_id: u64, pid: u32) -> Attribution {
        if let Some(hit) = self.state.read().await.by_cgroup.get(&cgroup_id) {
            return hit.clone();
        }

        let attribution = match self.container_id_for(cgroup_id, pid) {
            Some(id) => match self.name_for(&id).await {
                Some(name) => Attribution::Named { id, name },
                None => Attribution::Container { id },
            },
            None => Attribution::Unattributed { cgroup_id },
        };

        // Only a full resolution is cacheable. A bare container id means we
        // raced the event stream, and an unattributed result may just mean the
        // cgroup had not appeared yet -- both must be retried.
        if matches!(attribution, Attribution::Named { .. }) {
            self.state
                .write()
                .await
                .by_cgroup
                .insert(cgroup_id, attribution.clone());
        }

        attribution
    }

    fn container_id_for(&self, cgroup_id: u64, pid: u32) -> Option<String> {
        find_cgroup_by_ino(&self.cgroup_root, cgroup_id)
            .and_then(|path| {
                container_id_from_cgroup_path(&path.to_string_lossy()).map(str::to_owned)
            })
            .or_else(|| container_id_from_proc(pid))
    }

    async fn name_for(&self, id: &str) -> Option<String> {
        if let Some(name) = self.state.read().await.names.get(id) {
            return Some(name.clone());
        }
        // The container may have started since the last refresh. This is what
        // catches a container that execs within milliseconds of starting.
        self.refresh_names().await.ok()?;
        self.state.read().await.names.get(id).cloned()
    }

    async fn refresh_names(&self) -> Result<()> {
        let Some(docker) = &self.docker else {
            return Ok(());
        };

        let options = ListContainersOptionsBuilder::new().all(true).build();
        let containers = docker.list_containers(Some(options)).await?;

        let mut state = self.state.write().await;
        for container in containers {
            let (Some(id), Some(names)) = (container.id, container.names) else {
                continue;
            };
            if let Some(name) = names.first() {
                state
                    .names
                    .insert(id, name.trim_start_matches('/').to_owned());
            }
        }
        Ok(())
    }

    /// Follow the Docker event stream, keeping the cache honest. Returns when
    /// the stream ends or there is no Docker connection.
    pub async fn watch(&self) {
        let Some(docker) = &self.docker else {
            return;
        };

        let options = EventsOptionsBuilder::new().build();
        let mut stream = docker.events(Some(options));

        while let Some(message) = stream.next().await {
            let Ok(message) = message else { continue };
            let (Some(action), Some(actor)) = (message.action, message.actor) else {
                continue;
            };
            let Some(id) = actor.id else { continue };

            match action.as_str() {
                "start" => {
                    let _ = self.refresh_names().await;
                }
                "die" | "destroy" => self.forget(&id).await,
                _ => {}
            }
        }
    }

    /// Drop everything known about a container. Cgroup inodes can be reused
    /// after a cgroup is destroyed, so a stale entry could otherwise name a
    /// later container after the one it described is gone.
    async fn forget(&self, id: &str) {
        let mut state = self.state.write().await;
        state.names.remove(id);
        state
            .by_cgroup
            .retain(|_, attribution| attribution.container_id() != Some(id));
    }
}
