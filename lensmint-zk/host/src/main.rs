use anyhow::Context;
use host::{
    authenticity_image_id_hex, groth16_seal, load_receipt, make_signed_fixture, pick_recompress,
    prove_and_save, HashRecord, ProveRequest,
};
use lensmint_zk_core::GuestJournal;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        std::process::exit(2);
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "bench" => cmd_bench(&args),
        "prove" => cmd_prove(&args),
        "probe" => cmd_probe(&args),
        "image-id" => {
            println!("0x{}", authenticity_image_id_hex());
            Ok(())
        }
        "export-onchain" => cmd_export_onchain(&args),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => anyhow::bail!("unknown command: {other}"),
    }
}

fn print_usage() {
    eprintln!(
        "Usage:
  host probe [--quality N]          # no prove: scan recompress / pHash only
  host bench [--out DIR] [--quality N]
  host prove --record FILE.hash.json --jpeg FILE.jpg [--out DIR] [--quality N]
  host image-id                     # print authenticity IMAGE_ID for contracts
  host export-onchain --receipt FILE.receipt.bin [--out DIR]

bench builds a local fixture, picks a recompress demo, proves, writes receipt.
Set RISC0_DEV_MODE=1 for a fast fake receipt (tests only). Omit it for real Groth16 prove."
    );
}

fn cmd_probe(args: &[String]) -> anyhow::Result<()> {
    let preferred = flag_value(args, "--quality")
        .map(|s| s.parse::<u8>())
        .transpose()?;
    let (record, jpeg) = make_signed_fixture()?;
    let pick = pick_recompress(&jpeg, &record.phash, preferred)?;
    println!("sha256_original={}", record.sha256);
    println!("sha256_recompressed={}", pick.sha256_recompressed);
    println!("sha256_changed={}", record.sha256 != pick.sha256_recompressed);
    println!("phash0={}", record.phash);
    println!("phash1={}", pick.phash1_hex);
    println!("distance={}", pick.distance);
    println!("quality={}", pick.quality);
    println!("threshold=5");
    Ok(())
}

fn cmd_bench(args: &[String]) -> anyhow::Result<()> {
    let out = flag_value(args, "--out").unwrap_or_else(|| "out".into());
    let quality = flag_value(args, "--quality")
        .map(|s| s.parse::<u8>())
        .transpose()?
        .unwrap_or(50);

    let out_dir = PathBuf::from(out);
    std::fs::create_dir_all(&out_dir)?;

    let (record, jpeg) = make_signed_fixture()?;
    record.save_path(&out_dir.join(format!("{}.hash.json", record.uuid)))?;
    std::fs::write(out_dir.join(format!("{}.jpg", record.uuid)), &jpeg)?;

    run_prove(record, jpeg, quality, out_dir)
}

fn cmd_prove(args: &[String]) -> anyhow::Result<()> {
    let record_path = flag_value(args, "--record").context("missing --record")?;
    let jpeg_path = flag_value(args, "--jpeg").context("missing --jpeg")?;
    let out = flag_value(args, "--out").unwrap_or_else(|| "out".into());
    let quality = flag_value(args, "--quality")
        .map(|s| s.parse::<u8>())
        .transpose()?
        .unwrap_or(50);

    let record = HashRecord::load_path(PathBuf::from(record_path).as_path())?;
    let jpeg = std::fs::read(jpeg_path)?;
    run_prove(record, jpeg, quality, PathBuf::from(out))
}

fn run_prove(
    record: HashRecord,
    jpeg: Vec<u8>,
    quality: u8,
    out_dir: PathBuf,
) -> anyhow::Result<()> {
    let stats = prove_and_save(&ProveRequest {
        record,
        jpeg_bytes: jpeg,
        recompress_quality: quality,
        out_dir,
    })?;

    println!("prove_wall_ms={}", stats.prove_wall_ms);
    println!("receipt_bytes={}", stats.receipt_bytes);
    println!("receipt_path={}", stats.receipt_path.display());
    println!("recompress_quality={}", stats.recompress_quality);
    println!("distance={}", stats.distance);
    println!("phash0={}", stats.phash0_hex);
    println!("phash1={}", stats.phash1_hex);
    println!("threshold={}", stats.journal.threshold);
    println!("sha256_original={}", stats.sha256_original);
    println!("sha256_recompressed={}", stats.sha256_recompressed);
    println!(
        "sha256_changed={}",
        stats.sha256_original != stats.sha256_recompressed
    );
    println!("image_id=0x{}", authenticity_image_id_hex());
    Ok(())
}

fn cmd_export_onchain(args: &[String]) -> anyhow::Result<()> {
    let receipt_path = flag_value(args, "--receipt").context("missing --receipt")?;
    let out = flag_value(args, "--out").unwrap_or_else(|| ".".into());
    let out_dir = PathBuf::from(out);
    std::fs::create_dir_all(&out_dir)?;

    let receipt = load_receipt(PathBuf::from(receipt_path).as_path())?;
    receipt.verify(methods::AUTHENTICITY_ID)?;
    let journal = GuestJournal::from_abi(receipt.journal.as_ref())
        .map_err(|e| anyhow::anyhow!("decode ABI journal: {e}"))?;
    let seal = groth16_seal(&receipt)?;
    let journal_abi = journal
        .abi_encode()
        .map_err(|e| anyhow::anyhow!("encode ABI journal: {e}"))?;

    let seal_path = out_dir.join("seal.bin");
    let journal_path = out_dir.join("journal.abi");
    std::fs::write(&seal_path, &seal)?;
    std::fs::write(&journal_path, &journal_abi)?;

    println!("image_id=0x{}", authenticity_image_id_hex());
    println!("seal_path={}", seal_path.display());
    println!("seal_bytes={}", seal.len());
    println!("seal_selector=0x{}", hex::encode(&seal[..4.min(seal.len())]));
    println!("journal_abi_path={}", journal_path.display());
    println!("journal_abi_bytes={}", journal_abi.len());
    println!("journal_digest=0x{}", hex::encode(sha2_digest(&journal_abi)));
    Ok(())
}

fn sha2_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}
