//! The policy model: one reviewed TOML file per container.
//!
//! Every entry records why it exists, and automated passes never overwrite a
//! manual one. That rule is the whole point -- a policy you cannot trust to
//! survive the next `learn` run is a policy you have to re-review every time.
//!
//! Entries are sorted on save, because `git diff policy/` is the entire review
//! process. Unstable ordering would turn a one-line change into an unreadable
//! diff and the review would stop happening.

pub mod learn;
pub mod sync;

use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Why an entry is in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Written by a human. Never touched by an automated pass.
    Manual,
    /// Added by `quasar learn` from observed behaviour.
    Learned,
}

impl Source {
    pub fn is_manual(self) -> bool {
        matches!(self, Self::Manual)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRule {
    pub path: String,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRule {
    pub cidr: IpNet,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The window the learned entries were observed over, as `start/end`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_from: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<ExecRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<ExecRule>,
}

impl ExecRules {
    fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<EgressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<EgressRule>,
}

impl EgressRules {
    fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub meta: Meta,
    #[serde(default, skip_serializing_if = "ExecRules::is_empty")]
    pub exec: ExecRules,
    #[serde(default, skip_serializing_if = "EgressRules::is_empty")]
    pub egress: EgressRules,
}

/// What the policy says about one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Matched a deny rule. Deny always beats allow.
    Denied,
    /// No rule matched. This is what an alert is made of.
    Unbaselined,
}

impl Policy {
    pub fn check_exec(&self, path: &str) -> Decision {
        if self.exec.deny.iter().any(|rule| rule.path == path) {
            Decision::Denied
        } else if self.exec.allow.iter().any(|rule| rule.path == path) {
            Decision::Allowed
        } else {
            Decision::Unbaselined
        }
    }

    pub fn check_egress(&self, addr: IpAddr) -> Decision {
        if self
            .egress
            .deny
            .iter()
            .any(|rule| rule.cidr.contains(&addr))
        {
            Decision::Denied
        } else if self
            .egress
            .allow
            .iter()
            .any(|rule| rule.cidr.contains(&addr))
        {
            Decision::Allowed
        } else {
            Decision::Unbaselined
        }
    }

    /// Record an observed exec as `learned`. Returns whether anything changed.
    ///
    /// Nothing is added unless the observation is currently unbaselined, which
    /// is what keeps a manual entry -- allow *or* deny -- authoritative. A path
    /// a human deliberately denied is not quietly re-allowed by the next run.
    pub fn learn_exec(&mut self, path: &str) -> bool {
        if self.check_exec(path) != Decision::Unbaselined {
            return false;
        }
        self.exec.allow.push(ExecRule {
            path: path.to_owned(),
            source: Source::Learned,
            note: None,
        });
        true
    }

    /// Record an observed destination as a learned host route.
    ///
    /// A broad manual rule such as `10.0.0.0/8` already covers the address, so
    /// this adds nothing -- which is how a human generalising a range stops the
    /// file filling with one entry per host.
    pub fn learn_egress(&mut self, addr: IpAddr) -> bool {
        if self.check_egress(addr) != Decision::Unbaselined {
            return false;
        }
        let cidr = IpNet::new(addr, host_prefix_len(addr))
            .expect("a host prefix length is always valid for its address");
        self.egress.allow.push(EgressRule {
            cidr,
            source: Source::Learned,
            note: None,
        });
        true
    }

    /// Sort every list so a re-learn produces a minimal, readable git diff.
    fn sort(&mut self) {
        self.exec.allow.sort_by(|a, b| a.path.cmp(&b.path));
        self.exec.deny.sort_by(|a, b| a.path.cmp(&b.path));
        self.egress
            .allow
            .sort_by_key(|rule| (rule.cidr.network(), rule.cidr.prefix_len()));
        self.egress
            .deny
            .sort_by_key(|rule| (rule.cidr.network(), rule.cidr.prefix_len()));
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut sorted = self.clone();
        sorted.sort();
        let text = toml::to_string_pretty(&sorted).context("serialising policy")?;
        fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }
}

fn host_prefix_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Every container's policy, keyed by container name.
#[derive(Clone, Debug, Default)]
pub struct PolicySet {
    pub by_container: BTreeMap<String, Policy>,
}

impl PolicySet {
    /// Load every `*.toml` in a directory. A missing directory is an empty set,
    /// not an error: the service must start cleanly with no policy at all, so a
    /// bad or absent policy file can never prevent startup.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut by_container = BTreeMap::new();

        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self { by_container }),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            by_container.insert(name.to_owned(), Policy::load(&path)?);
        }

        Ok(Self { by_container })
    }

    pub fn save_dir(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        for (container, policy) in &self.by_container {
            policy.save(&policy_path(dir, container)?)?;
        }
        Ok(())
    }

    pub fn entry(&mut self, container: &str) -> &mut Policy {
        self.by_container.entry(container.to_owned()).or_default()
    }
}

/// A container name reaches us from the Docker API, so it is not trusted to be
/// a safe file name.
fn policy_path(dir: &Path, container: &str) -> Result<PathBuf> {
    if container.is_empty() || container.contains(['/', '\\', '\0']) || container.starts_with('.') {
        bail!("refusing to write a policy file for container name {container:?}");
    }
    Ok(dir.join(format!("{container}.toml")))
}
