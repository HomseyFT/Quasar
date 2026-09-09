//! CO-RE relocation against the deployment target's kernel.
//!
//! Development is on 6.19 and deployment is on 6.8. A relocation that fails
//! against 6.8 must surface here, not on the server. This is a pure userspace
//! check -- it relocates the object without loading it -- so it needs no root
//! and runs in CI.

use aya::{Btf, Endianness};

const TARGET_BTF: &str = "testdata/btf/ubuntu-6.8.0-139";

#[test]
fn exec_probe_relocates_against_target_kernel() {
    let Ok(btf) = Btf::parse_file(TARGET_BTF, Endianness::default()) else {
        panic!(
            "cannot read {TARGET_BTF}. Fetch it from the deployment target:\n    \
             scp nathan1@100.77.169.69:/sys/kernel/btf/vmlinux {TARGET_BTF}"
        );
    };

    relocate(&btf, quasar::loader::EXEC_OBJ, "exec");
}

/// fentry programs reference kernel function signatures, so this is the test
/// most likely to catch a 6.19-versus-6.8 divergence.
#[test]
fn connect_probe_relocates_against_target_kernel() {
    let Ok(btf) = Btf::parse_file(TARGET_BTF, Endianness::default()) else {
        panic!(
            "cannot read {TARGET_BTF}. Fetch it from the deployment target:\n    \
             scp nathan1@100.77.169.69:/sys/kernel/btf/vmlinux {TARGET_BTF}"
        );
    };
    relocate(&btf, quasar::loader::CONNECT_OBJ, "connect");
}

fn relocate(btf: &Btf, object: &[u8], what: &str) {
    let mut object = aya_obj::Object::parse(object)
        .unwrap_or_else(|e| panic!("the embedded {what} object does not parse: {e}"));

    object
        .relocate_btf(btf)
        .unwrap_or_else(|e| panic!("{what} probe fails CO-RE relocation against kernel 6.8: {e}"));
}
