use risc0_zkvm::{
    ProverOpts, 
    ApiClient,
    Asset, AssetRequest,
    SuccinctReceipt, 
    Receipt, ReceiptClaim,
};
use std::{
    fs,
    path::PathBuf,
    time::{Instant},
};
use anyhow;

use clap::{Parser, Subcommand};
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// proves a segment, and then lifts it
    Prove {
        /// input Segment blob
        #[arg(short, long)]
        in_seg: String,

        /// file to write lifted SuccinctReceipt to
        #[arg(short, long)]
        out_sr: String,
    },

    /// joins two SuccinctReceipts
    Join {
        /// left SuccinctReceipt
        #[arg(short, long)]
        left_sr: String,

        /// right SuccinctReceipt
        #[arg(short, long)]
        right_sr: String,

        /// file to write the resulting joined SuccinctReceipt to
        #[arg(short, long)]
        out_sr: String,
    },

    /// extract a Groth16 snark
    Snark {
        /// input SuccinctReceipt
        #[arg(short, long)]
        in_sr: String,

        /// file to write the Groth16 receipt to
        #[arg(short, long)]
        out_receipt: String,
    },

}


fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    match &args.command {
        Some(Commands::Prove{in_seg, out_sr}) => {
            let _sr = prove_and_lift(
                PathBuf::from(in_seg),
                PathBuf::from(out_sr),
            )?;
        },

        Some(Commands::Join {left_sr, right_sr, out_sr}) => {
            let _sr = join(
                PathBuf::from(left_sr),
                PathBuf::from(right_sr),
                PathBuf::from(out_sr),
            )?;
        },
        
        Some(Commands::Snark {in_sr, out_receipt}) => {
            let _r = to_snark(
                PathBuf::from(in_sr),
                PathBuf::from(out_receipt),
            )?;
        },

        _ => {}
    }

    Ok(())
}


fn prove_and_lift(
    in_seg_path: PathBuf,
    out_sr_path: PathBuf,
) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
    let r0_client = ApiClient::from_env()?;
    let prover_opts = ProverOpts::default();
    // fisrt prove
    let mut now = Instant::now();
    let segment_receipt = r0_client
        .prove_segment(
            &prover_opts,
            Asset::Path(in_seg_path),
            AssetRequest::Inline,
    )?; 
    let prove_dur = now.elapsed().as_secs();
    // and then lift
    let asset = Asset::try_from(segment_receipt)?.as_bytes()?;
    now = Instant::now();
    let succinct_receipt = r0_client
        .lift(
            &prover_opts,
            Asset::Inline(asset),
            AssetRequest::Inline
        )?;
    let lift_dur = now.elapsed().as_secs();
    println!("prove took `{} secs`, and lift `{} secs`.", prove_dur, lift_dur);
    let _ = fs::write(
        &out_sr_path,
        bincode::serialize(&succinct_receipt)?
    );
    Ok(succinct_receipt)
}

fn join(
    left_sr_path: PathBuf,
    right_sr_path: PathBuf,
    out_sr_path: PathBuf,
) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
    let r0_client = ApiClient::from_env()?;
    let prover_opts = ProverOpts::default();

    let now = Instant::now();
    let succinct_receipt = r0_client
        .join(
            &prover_opts,
            Asset::Path(left_sr_path),
            Asset::Path(right_sr_path),
            AssetRequest::Inline,
        )?;
    let dur = now.elapsed().as_secs();
    println!("join took `{dur} secs`");
    let _ = fs::write(
        &out_sr_path,
        bincode::serialize(&succinct_receipt)?
    );
    Ok(succinct_receipt)
}

fn to_snark(
    in_sr_path: PathBuf,
    out_receipt_path: PathBuf,
) -> anyhow::Result<Receipt> {
    let r0_client = ApiClient::from_env()?;
    let prover_opts = ProverOpts::default();
    // fist transform via identity_p254
    let now = Instant::now();
    let succinct_receipt = r0_client
        .identity_p254(
            &prover_opts,
            Asset::Path(in_sr_path),
            AssetRequest::Inline,
        )?;
    let dur = now.elapsed().as_secs();
    println!("identity_p254 took `{dur} secs`");
    // and then extract the compressed snark(Groth16)
    let asset = Asset::try_from(succinct_receipt)?.as_bytes()?;
    let now = Instant::now();
    let receipt = r0_client
        .compress(
            &prover_opts,
            Asset::Inline(asset),
            AssetRequest::Inline,
        )?;
    let dur = now.elapsed().as_secs();
    println!("compress took `{dur} secs`");
    let _ = fs::write(
        &out_receipt_path,
        bincode::serialize(&receipt)?
    );
    println!("your Groth16 receipt is ready!");
    Ok(receipt)
}