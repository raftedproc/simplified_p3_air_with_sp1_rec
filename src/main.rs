mod math_ops;
mod prog_exec;
mod register;
mod stark_primitives;

use hashbrown::HashMap;
use p3_field::extension::BinomialExtensionField;
use serde::de;
use sp1_sdk::SP1VerifyingKey;
use sp1_stark::air::SP1_PROOF_NUM_PV_ELTS;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use std::fs::File;

use clap::Parser;
use math_ops::{test_add, test_sub};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1CoreProofData, SP1Prover};
use sp1_stark::{
    inner_perm, AirOpenedValues, BabyBearPoseidon2Inner, Chip, ChipOpenedValues, InnerChallenger,
    MachineProof, SP1ProverOpts, ShardCommitment, ShardOpenedValues, ShardProof, StarkMachine,
    StarkVerifyingKey,
};

use std::io::Write;

use p3_uni_stark::{
    get_log_quotient_degree, prove, verify, OpenedValues, StarkGenericConfig, VerificationError,
};
use prog_exec::{generate_program_trace, ProgExec};
use register::init_regs;

use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use stark_primitives::{InnerBabyBearPoseidon2, P3Proof, BIN_OP_ROW_SIZE};

// type BabyBearExtentionField = ExtensionField<BabyBear>;
use p3_field::ExtensionField;

fn dummy_vk() -> StarkVerifyingKey<BabyBearPoseidon2> {
    let chips = vec![
        ("Byte".to_string(), 16),
        ("MemoryProgram".to_string(), 14),
        ("Program".to_string(), 14),
        ("AddSub".to_string(), 4),
        ("CPU".to_string(), 4),
        ("MemoryLocal".to_string(), 4),
    ];

    let chip_ordering = chips
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();

    StarkVerifyingKey {
        commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
        pc_start: BabyBear::zero(),
        chip_information: vec![],
        chip_ordering: chip_ordering,
    }
}

fn convert_opened_values_<F: p3_field::Field, EF: ExtensionField<F>>(
    // chip: &Chip<F, A>,
    p3_opended_values: &OpenedValues<EF>,
    log_degree: usize,
) -> ChipOpenedValues<EF> {
    // dummy values for pre and perm
    // let preprocessed_width = chip.preprocessed_width();
    // pre, main, perm must be unused
    let preprocessed = AirOpenedValues {
        local: vec![EF::zero(); BIN_OP_ROW_SIZE],
        next: vec![EF::zero(); BIN_OP_ROW_SIZE],
    };
    // let main_width = chip.width();
    // let permutation_width = chip.permutation_width();
    let permutation = AirOpenedValues {
        local: vec![EF::zero(); BIN_OP_ROW_SIZE * EF::D],
        next: vec![EF::zero(); BIN_OP_ROW_SIZE * EF::D],
    };

    let OpenedValues {
        trace_local,
        trace_next,
        quotient_chunks,
    } = p3_opended_values;
    // Put everything into main b/c main opnening values are handed over to
    // pcs::verify
    let main = AirOpenedValues {
        local: trace_local.clone(),
        next: trace_next.clone(),
    };

    // let quotient_width = chip.quotient_width();
    let quotient = quotient_chunks.clone();

    ChipOpenedValues {
        preprocessed,
        main,
        permutation,
        quotient,
        global_cumulative_sum: EF::zero(),
        local_cumulative_sum: EF::zero(),
        log_degree,
    }
}

// fn p3_proof_to_shardproof<SC: sp1_stark::StarkGenericConfig>(
fn p3_proof_to_shardproof(
    p3_proof: P3Proof,
    // air: ProgExec<BabyBear>,
) -> ShardProof<sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2> {
    // let shape = ProofShape { chip_information: vec![("p3_stark".to_string(), 42)] };
    let P3Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = p3_proof;

    let chip_opened_values = convert_opened_values_::<BabyBear, BinomialExtensionField<BabyBear, 4>>(
        &opened_values,
        degree_bits,
    );

    let shard_proof = ShardProof {
        commitment: ShardCommitment {
            global_main_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
            local_main_commit: commitments.trace,
            // local_main_commit: commitments.trace,
            permutation_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
            quotient_commit: commitments.quotient_chunks,
        },
        opened_values: ShardOpenedValues {
            chips: vec![chip_opened_values],
        },
        opening_proof,
        chip_ordering: HashMap::new(),
        public_values: vec![],
    };
    shard_proof
}

fn get_sp1_core_proofdata(
    p3_proof: P3Proof,
    /*air: ProgExec<BabyBear>*/
) -> SP1CoreProofData {
    let shard_proof = p3_proof_to_shardproof(p3_proof);
    let shard_proofs = vec![shard_proof];
    SP1CoreProofData(shard_proofs)
}

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

    let ops_len = ops.len();
    let mut prox_exec = ProgExec { ops, regs };
    let trace = generate_program_trace(&mut prox_exec, &cli);
    let trace_len = trace.values.len() / trace.width;

    let perm = inner_perm();
    let mut challenger = InnerChallenger::new(perm.clone());
    let inner = BabyBearPoseidon2Inner::default();
    let config = InnerBabyBearPoseidon2::new(inner.pcs);

    let p3_proof = prove(&config, &prox_exec, &mut challenger, trace, &vec![]);

    let mut challenger = InnerChallenger::new(perm.clone());
    verify(&config, &prox_exec, &mut challenger, &p3_proof, &vec![])?;

    // println!(
    //     "p3_proof {}",
    //     serde_json::to_string_pretty(&p3_proof).unwrap()
    // );

    let prover = SP1Prover::<DefaultProverComponents>::new();
    let opts = SP1ProverOpts::default();

    let core_proofdata = get_sp1_core_proofdata(p3_proof);
    let vk: StarkVerifyingKey<BabyBearPoseidon2> = dummy_vk();
    let log_quotient_degree = get_log_quotient_degree(&prox_exec, 0, 0);
    // Need to reduce a number of chips created down to 1
    let chip = Chip::new_(prox_exec.clone(), log_quotient_degree);
    let chips = vec![chip];
    let machine: StarkMachine<BabyBearPoseidon2, ProgExec<BabyBear>> = StarkMachine::new(
        BabyBearPoseidon2::new(),
        chips,
        SP1_PROOF_NUM_PV_ELTS,
        false,
    );

    let machine_proof = MachineProof {
        shard_proofs: core_proofdata.0.to_vec(),
    };
    let mut challenger = InnerChallenger::new(perm.clone());
    let chip = &machine.chips()[0];
    machine
        .verify_(&vk, &machine_proof, chip, &mut challenger)
        .unwrap();

    // prover.verify_(&core_proofdata, &chip, &sp1vk).unwrap();

    // let outer_proof = prover.wrap_bn254_(shard_proof, opts).unwrap();

    // println!(
    //     "wrapped_bn254 {:?}",
    //     serde_json::to_string(&outer_proof.proof).unwrap().len()
    // );

    // let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
    //     sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
    //         &outer_proof.vk,
    //         &outer_proof.proof,
    //     )
    // } else {
    //     sp1_sdk::install::try_install_circuit_artifacts("groth16")
    // };

    // let groth16_bn254_artifacts = sp1_sdk::install::try_install_circuit_artifacts("groth16");

    // let wrapped_bn254_proof: sp1_prover::Groth16Bn254Proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
    // let mut file = File::create("groth16.proof").expect("Could not create file!");
    // file.write_all(serde_json::to_string_pretty(&wrapped_bn254_proof).unwrap().as_bytes())
    //     .expect("Cannot write to the file!");

    // // vk from the initial setup
    // prover.verify_groth16_bn254_(&wrapped_bn254_proof,  &groth16_bn254_artifacts).unwrap();

    Ok(())
}
