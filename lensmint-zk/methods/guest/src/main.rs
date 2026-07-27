// Guest entry: read input, run statement, commit journal.

use lensmint_zk_core::{verify_authenticity, GuestInput};
use risc0_zkvm::guest::env;

fn main() {
    let input: GuestInput = env::read();
    let journal = verify_authenticity(&input).expect("guest statement failed");
    env::commit(&journal);
}
