mod math_ops;
mod prog_exec;
mod recursive_prover;
mod register;
mod stark_primitives;

use std::fmt::Debug;
use std::fs::File;

use clap::Parser;
use math_ops::{test_add, test_sub, I64MathOp};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_challenger::MultiField32Challenger;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2::Poseidon2;

use std::io::Write;

use p3_field::FieldAlgebra;
use p3_mersenne_31::Mersenne31;
use p3_uni_stark::{prove, verify};
use prog_exec::{generate_program_trace, ProgExec};
use recursive_prover::{generate_recursive_proover_trace, RecursiveProver};
use register::{init_regs, RegFile};
// use stark_primitives::{default_stark_config, ByteHash, Challenger, WrapChallenger, BIN_OP_ROW_SIZE};
use stark_primitives::{default_stark_config, ByteHash, Challenger};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use stark_primitives::Val;

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long, default_value_t = 1)]
    programs: u8,

    #[arg(short, long, default_value_t = 1)]
    repetitions: u16,
}

fn main() -> Result<(), impl Debug> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    let config = default_stark_config();

    let add_op = test_add();
    let sub_op = test_sub();

    let regs_num = 2;
    let mut regs = init_regs(regs_num);
    regs.int_regs[0] = 65535;
    regs.int_regs[1] = 4294901761;

    let mut ops = vec![];

    for i in 0..256 {
        if i % 2 == 0 {
            ops.push(add_op);
        } else {
            ops.push(sub_op);
        }
    }

    let mut randomx_air = ProgExec { ops, regs };
    let trace = generate_program_trace(&mut randomx_air, &cli);

    let byte_hash = ByteHash {};
    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&config, &randomx_air, &mut challenger, trace, &vec![]);
    println!("Proof commitments: {:#?}", serde_json::to_string(&proof).unwrap().len());

    let mut file = File::create("long.proof").expect("Could not create file!");
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .expect("Cannot write to the file!");


    // println!("Proof commitments: {:#?}", proof.commitments);
    // println!("Proof opened_values: {:#?}", proof.opened_values);
    // // println!("Proof opening_proof: {:?}", serde_json::to_string(&proof.opening_proof).unwrap());
    // println!("Proof degree_bits: {:#?}", proof.degree_bits);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    verify(&config, &randomx_air, &mut challenger, &proof, &vec![])?;

    let mut wrap_prover = RecursiveProver::<Val>::new();
    let mut wrap_challenger = Challenger::from_hasher(vec![], byte_hash);
    let rec_trace = generate_recursive_proover_trace(&mut wrap_prover, &randomx_air, &cli, &config, &mut wrap_challenger, &proof, &vec![]);


    // let mut rng = rand::thread_rng();
    // let mut wrap_perm = Poseidon2::new_from_rng(8, 22,& mut rng);
    // let mut wrap_challenger = WrapChallenger::new(wrap_perm);
    // let wrap_config = wrap_perm_stark_config();

    // let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    // change config to recursive
    // change challenger to recursive
    // let mut wrap_challenger:
    // type RecChallenger = MultiField32Challenger<Mersenne31, Bn254Fr, Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>, 3, 2>;
    // pub type OuterPcs = TwoAdicFriPcs<OuterVal, OuterDft, OuterValMmcs, OuterChallengeMmcs>;
    let rec_proof = prove(&config, &wrap_prover, &mut wrap_challenger, rec_trace, &vec![]);
    println!("Proof commitments: {:#?}", serde_json::to_string(&rec_proof).unwrap().len());

    let mut file = File::create("short.proof").expect("Could not create file!");
    file.write_all(serde_json::to_string_pretty(&rec_proof).unwrap().as_bytes())
        .expect("Cannot write to the file!");
    
    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    // CirclePcs::verify
    verify(&config, &wrap_prover, &mut challenger, &rec_proof, &vec![])
}
