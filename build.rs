use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

const PROBES: &[&str] = &["exec", "connect"];

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let bpf_dir = Path::new("bpf");

    println!("cargo:rerun-if-changed=bpf/common.h");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");
    println!("cargo:rerun-if-env-changed=CLANG");

    if !bpf_dir.join("vmlinux.h").exists() {
        panic!("bpf/vmlinux.h is missing -- run `make vmlinux`");
    }

    for probe in PROBES {
        compile_probe(probe, bpf_dir, &out_dir);
    }

    generate_bindings(bpf_dir, &out_dir);
}

fn compile_probe(probe: &str, bpf_dir: &Path, out_dir: &Path) {
    let src = bpf_dir.join(format!("{probe}.bpf.c"));
    println!("cargo:rerun-if-changed={}", src.display());

    let obj = out_dir.join(format!("{probe}.bpf.o"));
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());

    // -g is not optional: it is what emits the BTF that CO-RE relocation reads.
    let status = Command::new(&clang)
        .args(["-g", "-O2", "-target", "bpf", "-D__TARGET_ARCH_x86"])
        .args(["-mcpu=v3", "-Wall", "-Werror", "-c"])
        .arg("-I")
        .arg(bpf_dir)
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {clang}: {e}"));

    assert!(
        status.success(),
        "{clang} failed to compile {}",
        src.display()
    );
}

fn generate_bindings(bpf_dir: &Path, out_dir: &Path) {
    let header = bpf_dir.join("common.h");

    bindgen::Builder::default()
        .header(header.to_str().expect("common.h path is not utf-8"))
        .allowlist_type("exec_event")
        .allowlist_type("connect_event")
        .allowlist_var("QUASAR_.*")
        .derive_copy(true)
        .layout_tests(false)
        .generate()
        .expect("bindgen failed on bpf/common.h")
        .write_to_file(out_dir.join("common.rs"))
        .expect("failed to write generated bindings");
}
