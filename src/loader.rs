//! Loading and attaching the BPF objects.
//!
//! The objects are compiled by build.rs and embedded in the binary, which is
//! what lets a single static binary deploy to a host with no clang on it.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{MapData, PerCpuArray},
    programs::{FEntry, Lsm, TracePoint},
    Btf, Ebpf, EbpfLoader, Endianness,
};

// include_bytes! would give 1-byte alignment; the ELF parser needs more.
pub const EXEC_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/exec.bpf.o"));
pub const CONNECT_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/connect.bpf.o"));

/// The kernel functions the egress probes hook, paired with the program that
/// hooks each. The program name is ours; the function name must match the
/// kernel's, because that is what the attach resolves a BTF id against.
const EGRESS_PROBES: &[(&str, &str)] = &[
    ("quasar_tcp_v4_connect", "tcp_v4_connect"),
    ("quasar_tcp_v6_connect", "tcp_v6_connect"),
    ("quasar_udp_sendmsg", "udp_sendmsg"),
    ("quasar_udpv6_sendmsg", "udpv6_sendmsg"),
];

/// Events the kernel could not fit into a ring buffer.
///
/// This is a different failure from the userspace queue overflowing, and it
/// needs a different fix -- a bigger buffer rather than faster attribution --
/// so the two are counted and reported separately.
pub struct DropCounter(PerCpuArray<MapData, u64>);

impl DropCounter {
    /// Take the counter map out of a loaded object. Taking rather than
    /// borrowing leaves the object free for the ring buffer to take too.
    pub fn take(ebpf: &mut Ebpf, what: &str) -> Result<Self> {
        let map = ebpf
            .take_map("dropped")
            .with_context(|| format!("no dropped map in the {what} object"))?;
        Ok(Self(
            PerCpuArray::try_from(map).with_context(|| format!("{what} dropped map"))?,
        ))
    }

    pub fn total(&self) -> u64 {
        self.0
            .get(&0, 0)
            .map(|per_cpu| per_cpu.iter().sum())
            .unwrap_or(0)
    }
}

fn load(object: &[u8], btf_path: Option<&Path>, what: &str) -> Result<Ebpf> {
    let btf = btf_path
        .map(|p| {
            Btf::parse_file(p, Endianness::default())
                .with_context(|| format!("parsing BTF from {}", p.display()))
        })
        .transpose()?;

    let mut loader = EbpfLoader::new();
    if let Some(btf) = &btf {
        loader.btf(Some(btf));
    }
    loader
        .load(object)
        .with_context(|| format!("loading the {what} probe"))
}

/// Load the exec probe, relocating against `btf_path` if given and against the
/// running kernel otherwise. The override exists so the object can be checked
/// against the deployment target's BTF from a machine running a different
/// kernel.
pub fn load_exec(btf_path: Option<&Path>) -> Result<Ebpf> {
    load(EXEC_OBJ, btf_path, "exec")
}

pub fn load_connect(btf_path: Option<&Path>) -> Result<Ebpf> {
    load(CONNECT_OBJ, btf_path, "connect")
}

pub fn attach_exec(ebpf: &mut Ebpf) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut("quasar_exec")
        .context("no quasar_exec program in the exec object")?
        .try_into()?;

    program
        .load()
        .context("the verifier rejected quasar_exec")?;
    program
        .attach("sched", "sched_process_exec")
        .context("attaching to sched:sched_process_exec")?;

    Ok(())
}

/// Whether the kernel will accept a BPF LSM program.
///
/// `CONFIG_BPF_LSM=y` is not enough -- bpf also has to be in the active LSM
/// list, which is fixed at boot from the kernel command line. Checking here
/// turns "operation not supported" into a sentence that says what to do.
pub fn lsm_available() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|list| list.split(',').any(|lsm| lsm.trim() == "bpf"))
        .unwrap_or(false)
}

/// Attach the exec LSM hook.
///
/// Like fentry, an LSM program resolves its hook against the running kernel's
/// BTF, which is a different thing from the `--btf` relocation override.
pub fn attach_lsm(ebpf: &mut Ebpf) -> Result<()> {
    if !lsm_available() {
        anyhow::bail!(
            "BPF LSM is not in the kernel's active list. Append ',bpf' to the \
             lsm= parameter in the kernel command line and reboot; \
             `grep bpf /sys/kernel/security/lsm` should then list it"
        );
    }

    let btf = Btf::from_sys_fs().context("reading the running kernel's BTF")?;
    let program: &mut Lsm = ebpf
        .program_mut("quasar_bprm_check")
        .context("no quasar_bprm_check program in the exec object")?
        .try_into()?;

    program
        .load("bprm_check_security", &btf)
        .context("the verifier rejected quasar_bprm_check")?;
    program
        .attach()
        .context("attaching the LSM hook to bprm_check_security")?;

    Ok(())
}

/// Attach the egress probes.
///
/// fentry resolves the hooked function to a BTF id in the *running* kernel, so
/// this always reads the live BTF. That is a different thing from the `--btf`
/// relocation override, which only decides what the object's CO-RE relocations
/// are resolved against at load time.
pub fn attach_connect(ebpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("reading the running kernel's BTF")?;

    for (program_name, kernel_function) in EGRESS_PROBES {
        let program: &mut FEntry = ebpf
            .program_mut(program_name)
            .with_context(|| format!("no {program_name} program in the connect object"))?
            .try_into()?;

        program
            .load(kernel_function, &btf)
            .with_context(|| format!("the verifier rejected {program_name}"))?;
        program
            .attach()
            .with_context(|| format!("attaching fentry to {kernel_function}"))?;
    }

    Ok(())
}
