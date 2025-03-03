use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_field::{Field, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sha2::{Digest, Sha256};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use crate::math_ops::{no_op, MathOpFirstRow};
use crate::stark_primitives::LEFT_ARG;
use crate::{math_ops::I64MathOp, register::RegFile, stark_primitives::BIN_OP_ROW_SIZE, Cli};

pub fn dummy_32b_public_values(seed: u8) -> [u8; 32] {
    let mut public_values = [seed; 32];
    for i in 16..32 {
        public_values[i] = seed+1;
    }
    public_values
}

pub fn dummy_public_values_hash(global_nonce: &[u8; 32], local_nonce: &[u8; 32], hash_value: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(global_nonce);
    hasher.update(local_nonce);
    hasher.update(hash_value);
    hasher.finalize().into()
}

pub fn to_field_values<F: p3_field::Field>(values: &[u8]) -> Vec<F> {
    values.iter().map(|&b| F::from_canonical_u8(b)).collect()
}

#[derive(Clone, Debug)]
pub struct ProgExec<F: Field> {
    pub ops: Vec<I64MathOp<F>>,
    pub regs: RegFile,
    pub global_nonce: [u8;32],
    pub local_nonce: [u8;32],
    pub hash_value: [u8;32],
}

// This is a row size of a state representation.
// Includes register file ATM.
impl<F: Field> BaseAir<F> for ProgExec<F> {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

impl<AB: AirBuilder + AirBuilderWithPublicValues> Air<AB> for ProgExec<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // Use borrow trait for a FirstRow?
        let pub_values = builder.public_values().to_vec();
        // let local_pub_values = pub_values.clone();
        let mut when_first_row = builder.when_first_row();
        // WIP hardcode
        println!("public_values len {}", pub_values.len());
        for i in 0..pub_values.len().min(32usize) {
            when_first_row.assert_eq(pub_values[i], local[i + LEFT_ARG-1]);
        }

        builder
            .when_transition()
            .assert_eq(next[0], local[0] + AB::Expr::one());

        let op = I64MathOp::default();
        op.eval(builder);
    }
}

pub fn generate_program_trace<F: Field>(prog: &mut ProgExec<F>, cli: &Cli) -> RowMajorMatrix<F> {
    let num_of_ops = prog.ops.len() * cli.repetitions as usize * cli.programs as usize + 1;
    let next_pow_of_2 = num_of_ops.next_power_of_two();
    let mut values = Vec::with_capacity(BIN_OP_ROW_SIZE * next_pow_of_2);

    let public_values: Vec<F> = to_field_values(&dummy_public_values_hash(&prog.global_nonce, &prog.local_nonce, &prog.hash_value));
    let public_values_array = public_values.try_into().expect("must be 32 bytes");
    let mut first_row = MathOpFirstRow::new(public_values_array).consume_as_vec();
    // let first_row = vec![F::zero(); BIN_OP_ROW_SIZE];
    println!("generate_program_trace first_row len {}", first_row.len());

    values.append(&mut first_row); 

    // println!("generate_program_trace first_row {:?}", first_row);
    // values.append(&mut first_row);
    prog.regs.cnt += 1;

    // println!("generate_program_trace first_row {:?}", values);

    for _ in 0..cli.programs {
        for _ in 0..cli.repetitions {
            for op in prog.ops.iter_mut() {
                let mut next_record = op.generate(&mut prog.regs, &mut values);
                values.append(&mut next_record);
            }
        }
    }

    // find the next power of 2 and fill up the Matrix with NoOps up to the next pow of 2
    fill_up_with_no_ops(&mut values, &mut prog.regs);

    println!(
        "generate_program_trace values.len() {:?}  rows {}",
        values.len(),
        values.len() / BIN_OP_ROW_SIZE
    );
    RowMajorMatrix::new(values, BIN_OP_ROW_SIZE)
}

fn fill_up_with_no_ops<F: Field>(values: &mut Vec<F>, reg_file: &mut RegFile) {
    let actual_num_of_ops = values.len() / BIN_OP_ROW_SIZE;
    let next_pow_of_2 = actual_num_of_ops.next_power_of_two();
    let mut no_op = no_op();

    for _ in actual_num_of_ops..next_pow_of_2 {
        let mut next_record = no_op.generate(reg_file, values);
        values.append(&mut next_record);
    }
}

impl<F: PrimeField> MachineAir<F> for ProgExec<F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ProgExec".to_string()
    }

    fn generate_trace(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        todo!()
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        todo!()
    }

    fn preprocessed_width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}
