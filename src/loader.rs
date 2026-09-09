//! Loading and attaching the BPF objects.
//!
//! The objects are compiled by build.rs and embedded in the binary, which is
//! what lets a single static binary deploy to a host with no clang on it.

use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    programs::{FEntry, TracePoint},
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
];

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
