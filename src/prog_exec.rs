use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_field::AbstractField;
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::air::MachineAir;

use crate::{math_ops::I64MathOp, register::RegFile, stark_primitives::BIN_OP_ROW_SIZE, Cli};

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
    }
}

pub fn generate_program_trace<F: Field>(prog: &mut ProgExec<F>, cli: &Cli) -> RowMajorMatrix<F> {
    let mut values = Vec::with_capacity(BIN_OP_ROW_SIZE * prog.ops.len() * cli.repetitions as usize * cli.programs as usize);

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

impl<F: PrimeField> MachineAir<F> for ProgExec<F> {
    type Record = ExecutionRecord;

    type Program = Program;
    
    fn name(&self) -> String {
        "ProgExec".to_string()
    }
    
    fn generate_trace(&self, _input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        todo!()
    }
    
    fn included(&self, _shard: &Self::Record) -> bool {
        todo!()
    }

    fn preprocessed_width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }

}