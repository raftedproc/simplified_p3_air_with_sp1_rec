mod math_ops;
mod prog_exec;
mod register;
mod stark_primitives;

use ff::derive::bitvec::vec;
use hashbrown::HashMap;
use stark_primitives::InnerBabyBearPoseidon2;
use std::fs::File;

use clap::Parser;
use math_ops::{test_add, test_sub};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::SP1Prover;
use sp1_stark::{
    inner_perm, BabyBearPoseidon2Inner, InnerChallenger, SP1ProverOpts, ShardCommitment,
    ShardOpenedValues, ShardProof,
};

use std::io::Write;

use p3_uni_stark::{prove, verify, VerificationError};
use prog_exec::{generate_program_trace, ProgExec};
use register::init_regs;

use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long, default_value_t = 1)]
    programs: u8,

    #[arg(short, long, default_value_t = 1)]
    repetitions: u16,
}

fn main() -> Result<(), VerificationError> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    let add_op = test_add();
    let sub_op = test_sub();

    let regs_num = 2;
    let mut regs = init_regs(regs_num);
    regs.int_regs[0] = 65535;
    regs.int_regs[1] = 4294901761;

    let mut ops = vec![];

    for _ in 0..1 {
        for _ in 0..1 {
            for i in 0..256 {
                if i % 2 == 0 {
                    ops.push(add_op);
                } else {
                    ops.push(sub_op);
                }
            }
        }
    }

    let mut randomx_air = ProgExec { ops, regs };
    let trace = generate_program_trace(&mut randomx_air, &cli);

    let perm = inner_perm();
    let mut challenger = InnerChallenger::new(perm.clone());
    let inner = BabyBearPoseidon2Inner::default();
    let config = InnerBabyBearPoseidon2::new(inner.pcs);

    let p3_proof = prove(&config, &randomx_air, &mut challenger, trace, &vec![]);


    let mut challenger = InnerChallenger::new(perm.clone());
    verify(&config, &randomx_air, &mut challenger, &p3_proof, &vec![])?;

    let prover = SP1Prover::<DefaultProverComponents>::new();
    let opts = SP1ProverOpts::default();

    let input_proof = vec![0;32];
    let outer_proof = prover.wrap_bn254_(input_proof, opts).unwrap();

    // println!(
    //     "wrapped_bn254 {:?}",
    //     serde_json::to_string(&outer_proof.proof).unwrap().len()
    // );

    let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
        sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
            &outer_proof.vk,
            &outer_proof.proof,
        )
    } else {
        sp1_sdk::install::try_install_circuit_artifacts("groth16")
    };

    let groth16_proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
    let mut file = File::create("groth16_proof.json").expect("Could not create file!");
    file.write_all(serde_json::to_string_pretty(&groth16_proof).unwrap().as_bytes())
        .expect("Cannot write to the file!");

    // vk from the initial setup
    prover.verify_groth16_bn254_(&groth16_proof,  &groth16_bn254_artifacts).unwrap();

    Ok(())
}