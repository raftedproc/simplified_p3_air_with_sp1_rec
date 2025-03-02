use std::borrow::Borrow;
use std::{marker::PhantomData, ops::Neg};

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_field::Field;
use p3_matrix::Matrix;

use crate::{
    register::RegFile,
    stark_primitives::{BIN_OP_ROW_SIZE, CARRY, CARRY_START, LEFT_ARG, RESULT, RIGHT_ARG},
};

pub struct MathOpFirstRow<F: Field> {
    pub cnt: F,
    // the size must be 10 but this would prohibit 32 bytes public values hash
    pub flags: [F; LEFT_ARG - 2],
    pub public_values_sha256: [F; 32],
}

impl<F: Field> MathOpFirstRow<F> {
    // for generation of the first row
    pub fn new(public_values_sha256: [F; 32]) -> MathOpFirstRow<F> {
        let cnt = F::zero();
        let flags = [F::zero(); LEFT_ARG - 2];
        MathOpFirstRow {
            cnt,
            flags,
            public_values_sha256,
        }
    }

    pub fn consume_as_vec(&mut self) -> Vec<F> {
        let mut v = Vec::with_capacity(BIN_OP_ROW_SIZE);
        v.push(self.cnt);
        v.extend_from_slice(&self.flags);
        v.extend_from_slice(&self.public_values_sha256);
        v
    }
}

// impl<F> Borrow<MathOpFirstRow<F>> for [F] {
//     fn borrow(&self) -> &MathOpFirstRow<F> {
//         debug_assert_eq!(self.len(), BIN_OP_ROW_SIZE);
//         let (prefix, shorts, suffix) = unsafe { self.align_to::<MathOpFirstRow<F>>() };
//         debug_assert!(prefix.is_empty(), "Alignment should match");
//         debug_assert!(suffix.is_empty(), "Alignment should match");
//         debug_assert_eq!(shorts.len(), 1);
//         &shorts[0]
//     }
// }

#[derive(Clone, Copy, Debug)]
pub enum I64MathOps {
    Add,
    Sub,
    NoOp,
}

impl Default for I64MathOps {
    fn default() -> Self {
        I64MathOps::Add
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct I64MathOp<T> {
    pub op: I64MathOps,
    pub left_arg: i64,
    pub right_arg: i64,
    pub left_reg_idx: u8,
    pub right_reg_idx: u8,
    pub res_reg_idx: u8,
    pub _u: PhantomData<T>,
}

impl<F: Field> BaseAir<F> for I64MathOp<F> {
    fn width(&self) -> usize {
        BIN_OP_ROW_SIZE
    }
}

pub fn eval_add<AB: AirBuilder + AirBuilderWithPublicValues>(builder: &mut AB, is_real: AB::Expr) {
    let main = builder.main();
    let local = main.row_slice(0);
    // let is_real = local[1] + local[2];
    // let next = main.row_slice(1);

    let base = AB::F::from_canonical_u32(256);
    let one = AB::F::one();
    let mut when_is_real = builder.when(is_real.clone());

    when_is_real.assert_bool(is_real.clone());
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

    when_is_real.assert_zero(overflow_0.clone() * (overflow_0.clone() - base));
    when_is_real.assert_zero(overflow_1.clone() * (overflow_1.clone() - base));
    when_is_real.assert_zero(overflow_2.clone() * (overflow_2.clone() - base));
    when_is_real.assert_zero(overflow_3.clone() * (overflow_3.clone() - base));
    when_is_real.assert_zero(overflow_4.clone() * (overflow_4.clone() - base));
    when_is_real.assert_zero(overflow_5.clone() * (overflow_5.clone() - base));
    when_is_real.assert_zero(overflow_6.clone() * (overflow_6.clone() - base));
    when_is_real.assert_zero(overflow_7.clone() * (overflow_7.clone() - base));

    // If the carry is one, then the overflow must be the base.
    when_is_real.assert_zero(local[CARRY_START] * (overflow_0.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 1] * (overflow_1.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 2] * (overflow_2.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 3] * (overflow_3.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 4] * (overflow_4.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 5] * (overflow_5.clone() - base));
    when_is_real.assert_zero(local[CARRY_START + 6] * (overflow_6.clone() - base));

    // If the carry is not one, then the overflow must be zero.
    when_is_real.assert_zero((local[CARRY_START] - one.clone()) * overflow_0.clone());
    when_is_real.assert_zero((local[CARRY_START + 1] - one.clone()) * overflow_1.clone());
    when_is_real.assert_zero((local[CARRY_START + 2] - one.clone()) * overflow_2.clone());
    when_is_real.assert_zero((local[CARRY_START + 3] - one.clone()) * overflow_3.clone());
    when_is_real.assert_zero((local[CARRY_START + 4] - one.clone()) * overflow_4.clone());
    when_is_real.assert_zero((local[CARRY_START + 5] - one.clone()) * overflow_5.clone());
    when_is_real.assert_zero((local[CARRY_START + 6] - one.clone()) * overflow_6.clone());

    // Assert that the carry is either zero or one.
    when_is_real.assert_bool(local[CARRY_START]);
    when_is_real.assert_bool(local[CARRY_START + 1]);
    when_is_real.assert_bool(local[CARRY_START + 2]);
    when_is_real.assert_bool(local[CARRY_START + 3]);
    when_is_real.assert_bool(local[CARRY_START + 4]);
    when_is_real.assert_bool(local[CARRY_START + 5]);
    when_is_real.assert_bool(local[CARRY_START + 6]);
}

impl<AB: AirBuilder + AirBuilderWithPublicValues> Air<AB> for I64MathOp<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);

        eval_add(builder, local[1] + local[2]);
        // eval_add(builder, local[2]);
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
        I64MathOps::NoOp => {
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

pub fn populate_noop_trace_record<F: Field>(op: I64MathOps, cnt: u32) -> Vec<F> {
    let mut trace_record = Vec::with_capacity(BIN_OP_ROW_SIZE);

    trace_record.push(F::from_canonical_u32(cnt));
    let mut flags = populate_flags(op);
    trace_record.append(&mut flags);

    trace_record.append(&mut vec![F::zero(); BIN_OP_ROW_SIZE - LEFT_ARG]);

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
            I64MathOps::NoOp => populate_noop_trace_record(self.op, reg_file.cnt),
        };

        reg_file.cnt += 1;
        // values.append(trace_record.as_mut());
        trace_record
    }
}

pub fn add_op<Val: Field>() -> I64MathOp<Val> {
    I64MathOp::<Val> {
        op: I64MathOps::Add,
        left_arg: 0,
        right_arg: 1,
        left_reg_idx: 0,
        right_reg_idx: 1,
        res_reg_idx: 0,
        _u: PhantomData,
    }
}

pub fn sub_op<Val: Field>() -> I64MathOp<Val> {
    I64MathOp::<Val> {
        op: I64MathOps::Sub,
        left_arg: 0,
        right_arg: 1,
        left_reg_idx: 0,
        right_reg_idx: 1,
        res_reg_idx: 0,
        _u: PhantomData,
    }
}

pub fn no_op<Val: Field>() -> I64MathOp<Val> {
    I64MathOp::<Val> {
        op: I64MathOps::NoOp,
        left_arg: 0,
        right_arg: 0,
        left_reg_idx: 0,
        right_reg_idx: 0,
        res_reg_idx: 0,
        _u: PhantomData,
    }
}
