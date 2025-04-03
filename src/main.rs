mod math_ops;
mod prog_exec;
mod register;
mod stark_primitives;

use hashbrown::HashMap;
use p3_field::extension::BinomialExtensionField;
use sp1_primitives::consts::WORD_SIZE;
use sp1_recursion_core::air::{RecursionPublicValues, PV_DIGEST_NUM_WORDS, RECURSIVE_PROOF_NUM_PV_ELTS};
// use serde::de;
use sp1_sdk::SP1PublicValues;
use sp1_stark::air::SP1_PROOF_NUM_PV_ELTS;
use sp1_stark::baby_bear_poseidon2::{default_fri_config, BabyBearPoseidon2};
// use std::fs::File;

use clap::Parser;
use math_ops::{add_op, sub_op};
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::{SP1CoreProofData, SP1Prover};
use sp1_stark::{
    inner_perm, AirOpenedValues, BabyBearPoseidon2Inner, Chip, ChipOpenedValues, InnerChallenger, MachineProof, SP1ProverOpts, ShardCommitment, ShardOpenedValues, ShardProof, StarkMachine, StarkVerifyingKey, Word, PROOF_MAX_NUM_PVS
};
use std::borrow::BorrowMut;

// use std::io::Write;

use p3_uni_stark::{get_log_quotient_degree, prove, verify, OpenedValues, VerificationError};
use prog_exec::{
    dummy_32b_public_values, dummy_public_values_hash, generate_program_trace, to_field_values,
    ProgExec,
};
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
    public_values: Vec<BabyBear>, // must be [BabyBear; 32]
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

    println!(
        "chip_opened_values.main.local.len() {} {}",
        chip_opened_values.main.local.len(),
        chip_opened_values.log_degree,
    );

    let lengths = chip_opened_values
        .quotient
        .iter()
        .map(|x| x.len())
        .collect::<Vec<_>>();

    println!(
        "chip_opened_values.quotinent.len() {} widths {:?}",
        chip_opened_values.quotient.len(),
        lengths,
    );

    println!(
        "opening_proof.fri_proof.commit_phase_commits.len() 1 {}",
        opening_proof.fri_proof.commit_phase_commits.len()
    );
    let mut recursion_public_values_stream = [BabyBear::zero(); RECURSIVE_PROOF_NUM_PV_ELTS];
    let recursion_public_values: &mut RecursionPublicValues<_> =
        recursion_public_values_stream.as_mut_slice().borrow_mut();
    let mut commited_value_digest = [Word([BabyBear::zero(); WORD_SIZE]); PV_DIGEST_NUM_WORDS];
    for (i, word) in public_values.chunks(WORD_SIZE).enumerate() {
        commited_value_digest[i] = word.into_iter().map(|x| *x).collect();
    }
    recursion_public_values.committed_value_digest = commited_value_digest;
    let public_values = recursion_public_values.into_iter().collect();
    // let public_values_append_len = PROOF_MAX_NUM_PVS.max(public_values.len()) - public_values.len();
    // let mut public_values = public_values;
    // public_values.append(&mut vec![BabyBear::zero(); public_values_append_len]);

    let shard_proof = ShardProof {
        commitment: ShardCommitment {
            global_main_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
            local_main_commit: commitments.trace,
            permutation_commit: [BabyBear::zero(); sp1_stark::DIGEST_SIZE].into(),
            quotient_commit: commitments.quotient_chunks,
        },
        opened_values: ShardOpenedValues {
            chips: vec![chip_opened_values],
        },
        opening_proof,
        chip_ordering: HashMap::new(),
        public_values,
    };

    shard_proof
}

fn get_sp1_core_proofdata(
    p3_proof: P3Proof,
    public_values: Vec<BabyBear>,
    /*air: ProgExec<BabyBear>*/
) -> SP1CoreProofData {
    let shard_proof = p3_proof_to_shardproof(p3_proof, public_values);
    let shard_proofs = vec![shard_proof];
    SP1CoreProofData(shard_proofs)
}

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long, default_value_t = 1)]
    programs: u8,

    #[arg(short, long, default_value_t = 1)]
    repetitions: u16,

    #[arg(long, default_value_t = false)]
    recursive: bool,
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

    let add_op = add_op();
    let sub_op = sub_op();

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
    let global_nonce = dummy_32b_public_values(42);
    let local_nonce = dummy_32b_public_values(43);
    let mut hash_value = dummy_32b_public_values(44);
    let mut prox_exec = ProgExec {
        ops,
        regs,
        global_nonce,
        local_nonce,
        hash_value,
    };

    let trace = generate_program_trace(&mut prox_exec, &cli);

    let perm = inner_perm();
    let mut challenger = InnerChallenger::new(perm.clone());
    let inner = BabyBearPoseidon2Inner::default();
    let config = InnerBabyBearPoseidon2::new(inner.pcs);

    let public_values = dummy_public_values_hash(&global_nonce, &local_nonce, &hash_value);
    let public_values_as_field = to_field_values(&public_values);
    let p3_proof = prove(
        &config,
        &prox_exec,
        &mut challenger,
        trace,
        &public_values_as_field,
    );

    let mut challenger = InnerChallenger::new(perm.clone());
    verify(
        &config,
        &prox_exec,
        &mut challenger,
        &p3_proof,
        &public_values_as_field,
    )?;

    // println!(
    //     "p3_proof {}",
    //     serde_json::to_string_pretty(&p3_proof).unwrap()
    // );

    let log_quotient_degree = get_log_quotient_degree(&prox_exec, 0, 0);
    println!("main log_quotient_degree {}", log_quotient_degree);
    // Need to reduce a number of chips created down to 1
    // log_quotinent_degree is 4 for recursive and 1 for non-recursive
    let chip = Chip::new_(prox_exec, log_quotient_degree);
    let chips = vec![chip];
    let machine: StarkMachine<BabyBearPoseidon2, ProgExec<BabyBear>> = StarkMachine::new(
        BabyBearPoseidon2::new(),
        chips,
        SP1_PROOF_NUM_PV_ELTS,
        false,
    );

    let prover = SP1Prover::<DefaultProverComponents>::new();
    let opts = SP1ProverOpts::default();

    if cli.recursive {
        let shard_proof = p3_proof_to_shardproof(p3_proof, public_values_as_field);
        println!(
            "main shard_proof.public_values {}",
            serde_json::to_string(&shard_proof.public_values).unwrap(),
        );
        // println!("public_values length {}", shard_proof.public_values.len());

        let outer_proof = prover.wrap_bn254_(shard_proof, opts, &machine).unwrap();

        println!("recursive after wrap_bn254_");
        println!(
            "wrapped_bn254 outer_proof.proof.public_values {:?}",
            serde_json::to_string(&outer_proof.proof.public_values).unwrap()
        );

        let groth16_bn254_artifacts = if sp1_prover::build::sp1_dev_mode() {
            sp1_prover::build::try_build_groth16_bn254_artifacts_dev(
                &outer_proof.vk,
                &outer_proof.proof,
            )
        } else {
            sp1_sdk::install::try_install_circuit_artifacts("groth16")
        };

        let wrapped_bn254_proof: sp1_prover::Groth16Bn254Proof =
            prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);

        // let wrapped_bn254_proof = sp1_prover::Groth16Bn254Proof {
        //     public_inputs,
        //     encoded_proof,
        //     raw_proof,
        //     groth16_vkey_hash,
        // };

        // let wrapped_bn254_proof = sp1_prover::Groth16Bn254Proof {
        //     public_inputs,
        //     encoded_proof,
        //     raw_proof,
        //     groth16_vkey_hash,
        // };

        println!("encoded_proof 2 {}", wrapped_bn254_proof.encoded_proof);
        println!("raw_proof 2 {}", wrapped_bn254_proof.raw_proof);
        println!("public_inputs {:?}", wrapped_bn254_proof.public_inputs);
        // vk from the initial setup
        let sp1_public_values = SP1PublicValues::from(&public_values);
        println!("public_values {}", sp1_public_values.raw());
        prover
            .verify_groth16_bn254_(
                &wrapped_bn254_proof,
                &sp1_public_values,
                &groth16_bn254_artifacts,
            )
            .unwrap();
    } else {
        //     let mut public_values = dummy_public_values_hash(&global_nonce, &local_nonce, &hash_value);
        // public_values[0] = 234;
        // let public_values_as_field = to_field_values(&public_values);
        let core_proofdata = get_sp1_core_proofdata(p3_proof, public_values_as_field);
        let vk: StarkVerifyingKey<BabyBearPoseidon2> = dummy_vk();

        let machine_proof = MachineProof {
            shard_proofs: core_proofdata.0.to_vec(),
        };
        let mut challenger = InnerChallenger::new(perm.clone());
        let chip = &machine.chips()[0];
        machine
            .verify_(&vk, &machine_proof, chip, &mut challenger)
            .expect("Chip verification result must be Ok");
        // prover.verify_(&core_proofdata,  &chip, &sp1vk).unwrap();
    }

    Ok(())
}
