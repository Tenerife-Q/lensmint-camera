// Stub only. Real prove and receipt live in a later issue.

use methods::{AUTHENTICITY_ELF, AUTHENTICITY_ID};

fn main() {
    println!("AUTHENTICITY_ID={AUTHENTICITY_ID:?}");
    println!("guest ELF {} bytes", AUTHENTICITY_ELF.len());
    println!("statement tests: cargo test -p lensmint-zk-core");
}
