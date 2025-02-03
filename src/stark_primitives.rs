
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_uni_stark::{Proof, StarkConfig};

use sp1_stark::{InnerChallenge, InnerChallenger, InnerPcs};

pub(crate) type Val = BabyBear;
pub(crate) type Challenge = BinomialExtensionField<Val, 4>;
// pub(crate) type ByteHash = Keccak256Hash;
// pub(crate) type FieldHash = SerializingHasher32<ByteHash>;
// pub(crate) type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;
// pub(crate) type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
// pub(crate) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
// pub(crate) type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
// pub type Dft = Radix2DitParallel;
// pub(crate) type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

// pub const DIGEST_SIZE: usize = 1;

// pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
// pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
// pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

// pub type OuterChallenge = BinomialExtensionField<Val, 4>;
// pub type OuterPerm = Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
// pub type OuterHash = MultiField32PaddingFreeSponge<Val, Bn254Fr, OuterPerm, 3, 16, DIGEST_SIZE>;
// pub type OuterDigestHash = Hash<Val, Bn254Fr, DIGEST_SIZE>;
// pub type OuterDigest = [Bn254Fr; DIGEST_SIZE];
// pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
// pub type OuterValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, OuterHash, OuterCompress, 1>;
// pub type OuterChallengeMmcs = ExtensionMmcs<Val, OuterChallenge, OuterValMmcs>;
// pub type OuterDft = Radix2DitParallel;
// pub type OuterChallenger = MultiField32Challenger<
//     Val,
//     Bn254Fr,
//     OuterPerm,
//     OUTER_MULTI_FIELD_CHALLENGER_WIDTH,
//     OUTER_MULTI_FIELD_CHALLENGER_RATE,
// >;
// pub type OuterPcs = TwoAdicFriPcs<Val, OuterDft, OuterValMmcs, OuterChallengeMmcs>;

// pub(crate) type BabyBearKeccak = StarkConfig<Pcs, Challenge, Challenger>;
pub(crate) type InnerBabyBearPoseidon2 = StarkConfig<InnerPcs, InnerChallenge, InnerChallenger>;
// pub(crate) type BabyBearPoseidon2 = StarkConfig<OuterPcs, Challenge, OuterChallenger>;

pub type P3Proof = Proof<InnerBabyBearPoseidon2>;

// 1 instr cnt + 10 ops flags + 8 arg1 + 8 arg2 + 8 res + 7 carry
pub(crate) const BIN_OP_ROW_SIZE: usize = 42;
pub(crate) const CARRY: usize = 7;
pub(crate) const LEFT_ARG: usize = 11;
pub(crate) const RIGHT_ARG: usize = 19;
pub(crate) const RESULT: usize = 27;
pub(crate) const CARRY_START: usize = 35;
