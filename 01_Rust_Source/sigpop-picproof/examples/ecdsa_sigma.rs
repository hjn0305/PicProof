use circ::cfg::{
    clap::{self, Parser, ValueEnum},
    CircOpt,
};
use std::path::PathBuf;
use circ::ecdsa::pure_sigma::{prover, verifier, prover_sigmabus, verifier_sigmabus};
use rug::Integer;

#[derive(Debug, Parser)]
#[command(name = "zk", about = "The CirC ZKP runner")]
struct Options {
    #[arg(long, default_value = "pi_sigma")]
    proof: PathBuf,
    #[arg(long)]
    action: ProofAction,
    #[arg(long)]
    h_hi: Option<String>,
    #[arg(long)]
    h_lo: Option<String>,
    #[arg(long, default_value = "/data/doriansig/experiments/signed_images/camera_privkey.pem")]
    privkey: String,
    #[command(flatten)]
    circ: CircOpt,
}

#[derive(PartialEq, Debug, Clone, ValueEnum)]
enum ProofAction {
    Prove,
    Verify,
}

fn main() {
    env_logger::Builder::from_default_env()
        .format_level(false)
        .format_timestamp(None)
        .init();
    let opts = Options::parse();
    match (&opts.h_hi, &opts.h_lo) {
        (Some(h_hi_str), Some(h_lo_str)) => {
            let h_hi = Integer::from_str_radix(h_hi_str, 10).expect("Invalid h_hi");
            let h_lo = Integer::from_str_radix(h_lo_str, 10).expect("Invalid h_lo");
            match opts.action {
                ProofAction::Prove => {
                    prover_sigmabus(&h_hi, &h_lo, &opts.privkey, opts.proof);
                }
                ProofAction::Verify => {
                    verifier_sigmabus(&h_hi, &h_lo, opts.proof);
                }
            }
        }
        _ => {
            match opts.action {
                ProofAction::Prove => {
                    prover(opts.proof);
                }
                ProofAction::Verify => {
                    verifier(opts.proof);
                }
            }
        }
    }
}
