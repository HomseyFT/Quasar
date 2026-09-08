//! Loading and attaching the BPF objects.
//!
//! The objects are compiled by build.rs and embedded in the binary, which is
//! what lets a single static binary deploy to a host with no clang on it.

use std::path::Path;

use anyhow::{Context, Result};
use aya::{include_bytes_aligned, programs::TracePoint, Btf, Ebpf, EbpfLoader, Endianness};

// include_bytes! would give 1-byte alignment; the ELF parser needs more.
pub const EXEC_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/exec.bpf.o"));

/// Load the exec probe, relocating against `btf_path` if given and against the
/// running kernel otherwise. The override exists so the object can be checked
/// against the deployment target's BTF from a machine running a different
/// kernel.
pub fn load_exec(btf_path: Option<&Path>) -> Result<Ebpf> {
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
    loader.load(EXEC_OBJ).context("loading the exec probe")
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
