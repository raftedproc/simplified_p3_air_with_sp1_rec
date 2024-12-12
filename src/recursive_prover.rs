use p3_air::{Air, AirBuilder, BaseAir};
use p3_challenger::CanObserve;
use p3_challenger::CanSample;
use p3_challenger::FieldChallenger;
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_field::AbstractExtensionField;
use p3_field::Field;
// use p3_field::FieldAlgebra;
// use p3_field::FieldExtensionAlgebra;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_uni_stark::get_log_quotient_degree;
use p3_uni_stark::Domain;
// use p3_uni_stark::PcsError;
use p3_uni_stark::SymbolicAirBuilder;
use p3_uni_stark::VerificationError;
use p3_uni_stark::VerifierConstraintFolder;
use p3_uni_stark::{Proof, StarkGenericConfig};
use p3_field::AbstractField;

use itertools::Itertools;

use crate::stark_primitives::outer_perm;
use crate::stark_primitives::wrap_stark_config;
// use crate::stark_primitives::ByteHash;
// use crate::stark_primitives::Challenger;
use crate::stark_primitives::OuterChallenger;
use crate::{math_ops::I64MathOp, register::RegFile, stark_primitives::BIN_OP_ROW_SIZE, Cli};

// #[derive(Clone, Debug)]
pub struct RecursiveProver<F: Field> {
    // pub input: Proof<SC>,
    // pub ops: Vec<I64MathOp<F>>,
    // pub regs: RegFile,
    pub cnt: u32,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> RecursiveProver<F> {
    pub fn new() -> Self {
        Self {
            cnt: 0,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> BaseAir<F> for RecursiveProver<F> {
    fn width(&self) -> usize {
        4
    }
}

impl<AB: AirBuilder> Air<AB> for RecursiveProver<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);

        // builder
        //     .when_transition()
        //     .assert_eq(next[0], local[0] + AB::Expr::ONE);

        // builder.assert_one(local[1]);
        // builder.assert_one(local[2]);
        // builder.assert_one(local[3]);
        // for op in self.ops.iter() {
        //     op.eval(builder);
        // }
    }
}
pub fn verify_<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<SC>,
    public_values: &Vec<p3_uni_stark::Val<SC>>,
) -> Result<(), VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<p3_uni_stark::Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    let degree = 1 << degree_bits;
    let log_quotient_degree = get_log_quotient_degree::<p3_uni_stark::Val<SC>, A>(air, 0, public_values.len());
    let quotient_degree = 1 << log_quotient_degree;

    let pcs = config.pcs();
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = quotient_domain.split_domains(quotient_degree);

    let air_width = <A as BaseAir<p3_uni_stark::Val<SC>>>::width(air);
    // println!("air_width: {:?}", air_width);
    let valid_shape = opened_values.trace_local.len() == air_width
        && opened_values.trace_next.len() == air_width
        && opened_values.quotient_chunks.len() == quotient_degree
        && opened_values
            .quotient_chunks
            .iter()
            .all(|qc| qc.len() == <SC::Challenge as AbstractExtensionField<p3_uni_stark::Val<SC>>>::D);
    if !valid_shape {
        return Err(VerificationError::InvalidProofShape);
    }

    challenger.observe(commitments.trace.clone());
    let alpha: SC::Challenge = challenger.sample_ext_element();
    challenger.observe(commitments.quotient_chunks.clone());

    let zeta: SC::Challenge = challenger.sample();
    let zeta_next = trace_domain.next_point(zeta).unwrap();

    pcs.verify(
        vec![
            (
                commitments.trace.clone(),
                vec![(
                    trace_domain,
                    vec![
                        (zeta, opened_values.trace_local.clone()),
                        (zeta_next, opened_values.trace_next.clone()),
                    ],
                )],
            ),
            (
                commitments.quotient_chunks.clone(),
                quotient_chunks_domains
                    .iter()
                    .zip(&opened_values.quotient_chunks)
                    .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
                    .collect_vec(),
            ),
        ],
        opening_proof,
        challenger,
    )
    .map_err(|_| VerificationError::InvalidOpeningArgument)?;

    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other_domain)| {
                    other_domain.zp_at_point(zeta)
                        * other_domain.zp_at_point(domain.first_point()).inverse()
                })
                .product::<SC::Challenge>()
        })
        .collect_vec();

    let quotient = opened_values
        .quotient_chunks
        .iter()
        .enumerate()
        .map(|(ch_i, ch)| {
            ch.iter()
                .enumerate()
                .map(|(e_i, &c)| zps[ch_i] * SC::Challenge::monomial(e_i) * c)
                .sum::<SC::Challenge>()
        })
        .sum::<SC::Challenge>();

    let sels = trace_domain.selectors_at_point(zeta);

    let main = VerticalPair::new(
        RowMajorMatrixView::new_row(&opened_values.trace_local),
        RowMajorMatrixView::new_row(&opened_values.trace_next),
    );

    let mut folder = VerifierConstraintFolder {
        main,
        public_values,
        is_first_row: sels.is_first_row,
        is_last_row: sels.is_last_row,
        is_transition: sels.is_transition,
        alpha,
        accumulator: SC::Challenge::zero(),
    };
    air.eval(&mut folder);
    let folded_constraints = folder.accumulator;

    // Finally, check that
    //     folded_constraints(zeta) / Z_H(zeta) = quotient(zeta)
    if folded_constraints * sels.inv_zeroifier != quotient {
        return Err(VerificationError::OodEvaluationMismatch);
    }

    Ok(())
}

pub fn generate_recursive_proover_trace<A, SC, OSC>(
    // prog: &mut RecursiveProver<F>,
    air: &mut RecursiveProver<p3_uni_stark::Val<SC>>,
    recursive_air: &A,
    _cli: &Cli,
    config: &SC,
    challenger: &mut SC::Challenger,
    proof: &Proof<SC>,
    public_values: &Vec<p3_uni_stark::Val<SC>>,
) -> RowMajorMatrix<p3_uni_stark::Val<OSC>>
where
    SC: StarkGenericConfig,
    OSC: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<p3_uni_stark::Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    // WIP To be used in the future
    let wrap_config = wrap_stark_config();
    let wrap_perm = outer_perm();
    let mut wrap_challenger = OuterChallenger::new(wrap_perm.clone()).unwrap();

    verify_(config, recursive_air, challenger, proof, public_values).unwrap();

    let mut values = vec![];
    for _ in 0..4 {
        values.push(p3_uni_stark::Val::<OSC>::from_canonical_u32(air.cnt));
        values.push(p3_uni_stark::Val::<OSC>::one());
        values.push(p3_uni_stark::Val::<OSC>::one());
        values.push(p3_uni_stark::Val::<OSC>::one());
        air.cnt += 1;
    }

    // println!("values: {:?}", values);
    // let mut next_record = op.generate(&mut prog.regs, &mut values);
    // values.append(&mut next_record);

    RowMajorMatrix::new(values, 4)
}

