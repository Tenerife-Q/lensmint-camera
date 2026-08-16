// Guest: run statement, commit ABI journal bytes.

use lensmint_zk_core::{verify_authenticity, GuestInput};
use risc0_zkvm::guest::env;

fn main() {
    let input: GuestInput = env::read();
    let journal = verify_authenticity(&input).expect("guest statement failed");
    let bytes = journal.abi_encode().expect("journal abi encode failed");
    env::commit_slice(&bytes);
}
