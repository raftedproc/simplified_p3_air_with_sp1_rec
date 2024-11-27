use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Neg;

use clap::Parser;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_dft::Radix2DitParallel;
use p3_field::{AbstractField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
// use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::FieldMerkleTreeMmcs;
// use p3_mersenne_31::Mersenne31;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::thread_rng;
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::RC_16_30;
use sp1_prover::components::DefaultProverComponents;
use sp1_prover::SP1Prover;
use sp1_stark::baby_bear_poseidon2::BabyBearPoseidon2;
use sp1_stark::{SP1ProverOpts, UniConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use serde::ser::Serialize;
use p3_symmetric::Hash;

// use serde::Serialize;
use serde_json;

#[derive(Parser)]
pub struct Cli {
    #[arg(short, long, default_value_t = 1)]
    programs: u8,

    #[arg(short, long, default_value_t = 1)]
    repetitions: u16,
}

#[derive(Clone, Copy, Debug)]
pub enum I64MathOps {
    Add,
    Sub,
    Mul,
}

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type DigestHash = Hash<Val, Val, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs = FieldMerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    MyHash,
    MyCompress,
    8,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub const RANDOMX_ELF: &[u8] = include_bytes!("../../fluence-randomx-4-sp1/elf/riscv32im-succinct-zkvm-elf");


// 1 instr cnt + 10 ops flags + 8 arg1 + 8 arg2 + 8 res + 7 carry
const BIN_OP_ROW_SIZE: usize = 42;
const WORD_SIZE: usize = 8;
const CARRY: usize = 7;
const LEFT_ARG: usize = 11;
const RIGHT_ARG: usize = 19;
const RESULT: usize = 27;
const CARRY_START: usize = 35;

#[derive(Clone, Debug)]
pub struct RegFile {
    pub int_regs: Vec<i64>,
    pub cnt: u32,
}

impl RegFile {
    pub fn new(reg_file_size: usize) -> Self {
        let int_regs = vec![0; reg_file_size];
        let cnt = 0;
        RegFile { int_regs, cnt }
    }
}

pub fn init_regs(regs_num: usize) -> RegFile {
    let mut regs = RegFile::new(regs_num);
    for i in 0..regs_num {
        let mul = i as u8;
        regs.int_regs[i] = i64::from_le_bytes([
            1 * mul,
            2 * mul,
            3 * mul,
            4 * mul,
            5 * mul,
            6 * mul,
            7 * mul,
            8 * mul,
        ]);
    }
    regs
}

#[derive(Clone, Copy, Debug)]
pub struct I64MathOp<T> {
    pub op: I64MathOps,
    pub left_arg: i64,
    pub right_arg: i64,
    pub res: [T; WORD_SIZE],
    pub carry: [T; CARRY],
    pub left_reg_idx: u8,
    pub right_reg_idx: u8,
    pub res_reg_idx: u8,
}

impl<F: Field> BaseAir<F> for I64MathOp<F> {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

pub fn eval_add<AB: AirBuilder>(builder: &mut AB, is_real: AB::Var) {
    let main = builder.main();
    let local = main.row_slice(0);
    // let next = main.row_slice(1);

    let base = AB::F::from_canonical_u32(256);
    let one = AB::F::one();
    let mut is_real = builder.when(is_real);

    // left = local[11..19];
    // right = local[19..27];
    // res = local[27..35];
    // carry = local[35..42];

    // For each limb, assert that difference between the carried result and the non-carried
    // result is either zero or the base.
    let overflow_0 = local[LEFT_ARG] + local[RIGHT_ARG] - local[RESULT];
    let overflow_1 =
        local[LEFT_ARG + 1] + local[RIGHT_ARG + 1] - local[RESULT + 1] + local[CARRY_START];
    let overflow_2 =
        local[LEFT_ARG + 2] + local[RIGHT_ARG + 2] - local[RESULT + 2] + local[CARRY_START + 1];
    let overflow_3 =
        local[LEFT_ARG + 3] + local[RIGHT_ARG + 3] - local[RESULT + 3] + local[CARRY_START + 2];
    let overflow_4 =
        local[LEFT_ARG + 4] + local[RIGHT_ARG + 4] - local[RESULT + 4] + local[CARRY_START + 3];
    let overflow_5 =
        local[LEFT_ARG + 5] + local[RIGHT_ARG + 5] - local[RESULT + 5] + local[CARRY_START + 4];
    let overflow_6 =
        local[LEFT_ARG + 6] + local[RIGHT_ARG + 6] - local[RESULT + 6] + local[CARRY_START + 5];
    let overflow_7 =
        local[LEFT_ARG + 7] + local[RIGHT_ARG + 7] - local[RESULT + 7] + local[CARRY_START + 6];

    is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
    is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
    is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
    is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));
    is_real.assert_zero(overflow_4.clone() * (overflow_4.clone() - base));
    is_real.assert_zero(overflow_5.clone() * (overflow_5.clone() - base));
    is_real.assert_zero(overflow_6.clone() * (overflow_6.clone() - base));
    is_real.assert_zero(overflow_7.clone() * (overflow_7.clone() - base));

    // If the carry is one, then the overflow must be the base.
    is_real.assert_zero(local[CARRY_START] * (overflow_0.clone() - base));
    is_real.assert_zero(local[CARRY_START + 1] * (overflow_1.clone() - base));
    is_real.assert_zero(local[CARRY_START + 2] * (overflow_2.clone() - base));
    is_real.assert_zero(local[CARRY_START + 3] * (overflow_3.clone() - base));
    is_real.assert_zero(local[CARRY_START + 4] * (overflow_4.clone() - base));
    is_real.assert_zero(local[CARRY_START + 5] * (overflow_5.clone() - base));
    is_real.assert_zero(local[CARRY_START + 6] * (overflow_6.clone() - base));

    // // If the carry is not one, then the overflow must be zero.
    is_real.assert_zero((local[CARRY_START] - one.clone()) * overflow_0.clone());
    is_real.assert_zero((local[CARRY_START + 1] - one.clone()) * overflow_1.clone());
    is_real.assert_zero((local[CARRY_START + 2] - one.clone()) * overflow_2.clone());
    is_real.assert_zero((local[CARRY_START + 3] - one.clone()) * overflow_3.clone());
    is_real.assert_zero((local[CARRY_START + 4] - one.clone()) * overflow_4.clone());
    is_real.assert_zero((local[CARRY_START + 5] - one.clone()) * overflow_5.clone());
    is_real.assert_zero((local[CARRY_START + 6] - one.clone()) * overflow_6.clone());

    // // Assert that the carry is either zero or one.
    builder.assert_bool(local[CARRY_START]);
    builder.assert_bool(local[CARRY_START + 1]);
    builder.assert_bool(local[CARRY_START + 2]);
    builder.assert_bool(local[CARRY_START + 3]);
    builder.assert_bool(local[CARRY_START + 4]);
    builder.assert_bool(local[CARRY_START + 5]);
    builder.assert_bool(local[CARRY_START + 6]);
}

impl<AB: AirBuilder> Air<AB> for I64MathOp<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        match self.op {
            I64MathOps::Add => eval_add(builder, local[1]),
            I64MathOps::Sub => eval_add(builder, local[2]),
            I64MathOps::Mul => todo!(),
        }
    }
}

pub fn populate_flags<F: Field>(op: I64MathOps) -> Vec<F> {
    let mut flags = vec![F::zero(); 10];
    match op {
        I64MathOps::Add => {
            flags[0] = F::one();
        }
        I64MathOps::Sub => {
            flags[1] = F::one();
        }
        I64MathOps::Mul => {
            flags[2] = F::one();
        }
    }
    flags
}

pub fn populate_add_trace_record<F: Field>(
    op: I64MathOps,
    cnt: u32,
    left: i64,
    right: i64,
    res: i64,
) -> Vec<F> {
    let mut trace_record = Vec::with_capacity(BIN_OP_ROW_SIZE);

    trace_record.push(F::from_canonical_u32(cnt));
    let mut flags = populate_flags(op);
    trace_record.append(&mut flags);

    let left_as_b = left.to_le_bytes();
    let right_as_b = right.to_le_bytes();
    let res_as_b = res.to_le_bytes();

    // println!("left_as_b: {:?}", left_as_b);
    for el in left_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    // println!("right_as_b: {:?}", right_as_b);
    for el in right_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    for el in res_as_b {
        trace_record.push(F::from_canonical_u8(el));
    }

    let mut prev_carry_value = 0u8;
    for i in 0..CARRY {
        if (left_as_b[i] as u32) + (right_as_b[i] as u32) + (prev_carry_value as u32) > 255 {
            trace_record.push(F::one());
            prev_carry_value = 1;
        } else {
            trace_record.push(F::zero());
            prev_carry_value = 0;
        };
    }

    trace_record
}

impl<F: Field> I64MathOp<F> {
    pub fn generate(&mut self, reg_file: &mut RegFile, _values: &mut Vec<F>) -> Vec<F> {
        let left_idx = self.left_reg_idx as usize;
        let right_idx = self.right_reg_idx as usize;
        let res_idx = self.res_reg_idx as usize;

        self.left_arg = reg_file.int_regs[left_idx];
        self.right_arg = reg_file.int_regs[right_idx];

        let trace_record = match self.op {
            I64MathOps::Add => {
                let r = self.left_arg.wrapping_add(self.right_arg);
                reg_file.int_regs[res_idx as usize] = r;
                populate_add_trace_record(self.op, reg_file.cnt, self.left_arg, self.right_arg, r)
            }
            I64MathOps::Sub => {
                let right_arg = self.right_arg.neg();
                let r = self.left_arg.wrapping_add(right_arg);
                reg_file.int_regs[res_idx as usize] = r;
                populate_add_trace_record(self.op, reg_file.cnt, self.left_arg, right_arg, r)
            }
            I64MathOps::Mul => todo!(),
        };

        reg_file.cnt += 1;
        // values.append(trace_record.as_mut());
        trace_record
    }
}

#[derive(Clone, Debug)]
pub struct ProgExec<F: Field> {
    pub ops: Vec<I64MathOp<F>>,
    pub regs: RegFile,
}

// This is a row size of a state representation.
// Includes register file ATM.
impl<F: Field> BaseAir<F> for ProgExec<F> {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

impl<AB: AirBuilder> Air<AB> for ProgExec<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        builder
            .when_transition()
            .assert_eq(next[0], local[0] + AB::Expr::one());

        for op in self.ops.iter() {
            op.eval(builder);
        }
    }
}

pub fn generate_program_trace<F: Field>(prog: &mut ProgExec<F>, cli: &Cli) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(BIN_OP_ROW_SIZE * prog.ops.len() * cli.repetitions as usize);

    for _ in 0..cli.programs {
        for _ in 0..cli.repetitions {
            for op in prog.ops.iter_mut() {
                    let mut next_record = op.generate(&mut prog.regs, &mut values);
                    values.append(&mut next_record);
            }
        }
    }
    
    RowMajorMatrix::new(values, BIN_OP_ROW_SIZE)
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

    let add_op = I64MathOp::<Val> {
        op: I64MathOps::Add,
        left_arg: 0,
        right_arg: 1,
        carry: [Val::zero(); 7],
        res: [Val::zero(); 8],
        left_reg_idx: 0,
        right_reg_idx: 1,
        res_reg_idx: 0,
    };

    let neg_op = I64MathOp::<Val> {
        op: I64MathOps::Sub,
        left_arg: 0,
        right_arg: 1,
        carry: [Val::zero(); 7],
        res: [Val::zero(); 8],
        left_reg_idx: 0,
        right_reg_idx: 1,
        res_reg_idx: 0,
    };

    let regs_num = 2;
    let mut regs = init_regs(regs_num);
    regs.int_regs[0] = 65535;
    regs.int_regs[1] = 4294901761;

    let mut ops = vec![];

    for i in 0..256 {
        if i % 2 == 0 {
            ops.push(add_op);
        } else {
            ops.push(neg_op);
        }
    }

    let mut air = ProgExec { ops, regs };
    let trace = generate_program_trace::<Val>(&mut air, &cli);

    // let config = default_fri_config();
    let config = UniConfig(BabyBearPoseidon2::new());

    // let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let mut challenger = Challenger::new(config.0.perm.clone());
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);
    // println!("proof len {:#?}", serde_json::to_string(&proof).unwrap());

    // let prover = SP1Prover::<DefaultProverComponents>::new();
    // let (pk, vk) = prover.setup(RANDOMX_ELF);

    // let opts = SP1ProverOpts::default();

    // let context = SP1Context::default();
    // let micro_cache = vec![42u8; 10];
    // let mut stdin = SP1Stdin::new();
    // stdin.write_vec(micro_cache.clone());
    // stdin.write_slice(&micro_cache);

    // // // let _ = prover.execute(RANDOMX_ELF, &stdin, context.clone());

    // let core_proof = prover.prove_core(&pk, &stdin, opts, context).unwrap();
    // println!("core_proof {:#?}", core_proof.proof.0[0].commitment);
    // println!("core_proof {:#?}", core_proof.proof.0[1].commitment);

    // let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let mut challenger = Challenger::new(config.0.perm.clone());
    verify(&config, &air, &mut challenger, &proof, &vec![])
}
