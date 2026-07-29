// Host helpers: HashRecord → pHash1 → prove → receipt on disk.

mod fixture;
mod hash_record;
mod phash;
mod prove;
mod recompress_pick;

pub use fixture::make_signed_fixture;
pub use hash_record::HashRecord;
pub use phash::{gradient_phash_hex, recompress_jpeg, sha256_hex};
pub use prove::{load_receipt, prove_and_save, BenchStats, ProveRequest};
pub use recompress_pick::{pick_recompress, RecompressPick};
