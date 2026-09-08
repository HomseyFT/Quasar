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

    let mut object = aya_obj::Object::parse(quasar::loader::EXEC_OBJ)
        .expect("the embedded exec object does not parse");

    object
        .relocate_btf(&btf)
        .expect("exec probe fails CO-RE relocation against kernel 6.8");
}
