use risc0_zkvm::{
    ProverOpts, 
    ApiClient,
    ExecutorEnv,
    Asset, AssetRequest,
    SuccinctReceipt,
    Receipt, ReceiptClaim,
    VerifierContext, SuccinctReceiptVerifierParameters, 
    recursion::MerkleGroup,
};
use risc0_circuit_recursion::control_id::{ALLOWED_CONTROL_ROOT, BN254_IDENTITY_CONTROL_ID};
use risc0_zkp::core::hash::poseidon_254::Poseidon254HashSuite;

use std::{
    fs,
    path::PathBuf,
    time::{Instant},
    collections::BTreeMap,
};

use rand::Rng;  
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
    /// segment an elf into parts according to the given po2_limit
    Segment {
        /// the elf
        #[arg(short, long)]
        elf: String,

        /// segment limit size
        #[arg(short, long, default_value = "20")]
        po2: String,

        /// path to write segment blobs to
        #[arg(short, long)]
        out_path: String,                
    },

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
    // join_all()?;
    let args = Cli::parse();
    match &args.command {
        Some(Commands::Segment {elf, po2, out_path}) => {
            let _ = segment_elf(
                PathBuf::from(elf),
                u32::from_str_radix(po2, 10)?,
                PathBuf::from(out_path),
            )?;
        },

        Some(Commands::Prove {in_seg, out_sr}) => {
            let _ = prove_and_lift(
                PathBuf::from(in_seg),
                PathBuf::from(out_sr),
            )?;
        },

        Some(Commands::Join {left_sr, right_sr, out_sr}) => {
            let _ = join(
                PathBuf::from(left_sr),
                PathBuf::from(right_sr),
                PathBuf::from(out_sr),
            )?;
        },
        
        Some(Commands::Snark {in_sr, out_receipt}) => {
            let _ = to_snark(
                PathBuf::from(in_sr),
                PathBuf::from(out_receipt),
            )?;
        },

        _ => {}
    }

    Ok(())
}

fn _join_all() -> anyhow::Result<()> {
    let mut to_be_joined: Vec<Asset> = vec![];
    let mut joined: Vec<Asset> = vec![];
    // read segs
    for i in 0..5 {        
        let sr: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(
            &std::fs::read(format!("segs/lifted/{i}.sr")).unwrap()
        )?;
        to_be_joined.push(
            Asset::try_from(sr)?
        );
    }

    let r0_client = ApiClient::from_env()?;
    let mut lucky: Option<Asset> = None;
    for i in 0..3 {
        println!("round {i}");
        for j in (0..to_be_joined.len()).step_by(2) {            
            if j == to_be_joined.len() - 1 {
                // the lucky segment advances to the next round automatically
                lucky = Some(to_be_joined[j].clone());
                break;
            }
            println!("join {}-{}", j, j+1);
            let succinct_receipt = r0_client
                .join(
                    &ProverOpts::succinct(),
                    to_be_joined[j].clone(),
                    to_be_joined[j+1].clone(),
                    AssetRequest::Inline,
                )?;
            let _ = succinct_receipt.verify_integrity()?;
            joined.push(Asset::try_from(succinct_receipt)?);
        }
        to_be_joined.clear();
        to_be_joined.extend_from_slice(&joined);
        if lucky.is_some() {
            to_be_joined.push(lucky.clone().unwrap());
        }
        joined.clear();
    }
    let stark: SuccinctReceipt<ReceiptClaim> = bincode::deserialize(&lucky.unwrap().as_bytes()?)?;
    let _ = fs::write(
        PathBuf::from("segs/joined/x.sr"),
        bincode::serialize(&stark)?
    );

    Ok(())
}

fn segment_elf(
    elf_path: PathBuf,
    limit_po2: u32,
    out_path: PathBuf,
) -> anyhow::Result<()> {
    let r0_client = ApiClient::from_env()?;
    let exec_env = {
        let mut rng = rand::thread_rng();
        let noise: Vec<u32> = (0..50_000).map(|_| rng.gen_range(0..u32::MAX as u32)).collect();
        ExecutorEnv::builder()
            .segment_limit_po2(limit_po2)
            .write(&noise)
            .unwrap()
            .build()
            .unwrap()
    };  
    let segment_callback = |_segment_info, _asset| -> anyhow::Result<()> {
        Ok(())
    };
    let _session_info = r0_client.execute(
        &exec_env,
        Asset::Path(elf_path),
        AssetRequest::Path(out_path),
        segment_callback,
    )?;
    Ok(())
}


fn prove_and_lift(
    in_seg_path: PathBuf,
    out_sr_path: PathBuf,
) -> anyhow::Result<SuccinctReceipt<ReceiptClaim>> {
    let r0_client = ApiClient::from_env()?;
    // fisrt prove
    let mut now = Instant::now();
    let segment_receipt = r0_client
        .prove_segment(
            &ProverOpts::succinct(),
            Asset::Path(in_seg_path),
            AssetRequest::Inline,
    )?; 
    let prove_dur = now.elapsed().as_secs();
    let _ = segment_receipt.verify_integrity_with_context(
        &VerifierContext::with_succinct_verifier_parameters(
            VerifierContext::default(),
            SuccinctReceiptVerifierParameters::default(),
        )
    )?;
    // and then lift
    let asset = Asset::try_from(segment_receipt)?.as_bytes()?;
    now = Instant::now();
    let succinct_receipt = r0_client
        .lift(
            &ProverOpts::succinct(),
            Asset::Inline(asset),
            AssetRequest::Inline
        )?;
    let lift_dur = now.elapsed().as_secs();
    println!("prove took `{} secs`, and lift `{} secs`.", prove_dur, lift_dur);
    let _ = succinct_receipt.verify_integrity()?;
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
    let now = Instant::now();
    let succinct_receipt = r0_client
        .join(
            &ProverOpts::succinct(),
            Asset::Path(left_sr_path),
            Asset::Path(right_sr_path),
            AssetRequest::Inline,
        )?;
    let _ = succinct_receipt.verify_integrity()?;
    // println!("hash fn: {}", succinct_receipt.hashfn);
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
    // fist transform via identity_p254
    let now = Instant::now();
    let p254_receipt = r0_client
        .identity_p254(
            &ProverOpts::succinct(),
            Asset::Path(in_sr_path),
            AssetRequest::Inline,
        )?;
    let dur = now.elapsed().as_secs();
    println!("identity_p254 took `{dur} secs`");
    //
    // let now = Instant::now();
    let verifier_parameters = SuccinctReceiptVerifierParameters {
        control_root: MerkleGroup::new(vec![BN254_IDENTITY_CONTROL_ID])
            .unwrap()
            .calc_root(Poseidon254HashSuite::new_suite().hashfn.as_ref()),
        inner_control_root: Some(ALLOWED_CONTROL_ROOT),
        ..Default::default()
    };
    let _ = p254_receipt.verify_integrity_with_context(
        &VerifierContext::empty()
            .with_suites(BTreeMap::from([(
                "poseidon_254".to_string(),
                Poseidon254HashSuite::new_suite(),
            )]))
            .with_succinct_verifier_parameters(verifier_parameters),
    ).unwrap();
    // let dur = now.elapsed().as_secs();
    // println!("verification of identity_p254 took `{dur} secs`");

    // and then extract the compressed snark(Groth16)
    let asset = Asset::try_from(p254_receipt)?.as_bytes()?;
    let now = Instant::now();    
    let receipt = r0_client
        .compress(
            &ProverOpts::groth16(),
            Asset::Inline(asset),
            AssetRequest::Inline,
        )?;
    let dur = now.elapsed().as_secs();
    println!("compress took `{dur} secs`");
    let _ = fs::write(
        &out_receipt_path,
        bincode::serialize(&receipt)?
    );
    println!("your Groth16 receipt is ready!`");
    Ok(receipt)
}