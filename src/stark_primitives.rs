use std::marker::PhantomData;

use p3_baby_bear::BabyBear;
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254, FFBn254Fr};
// TBU with the recent Plonky3
// use p3_bn254_fr::Poseidon2Bn254;
use p3_challenger::{HashChallenger, MultiField32Challenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::FieldMerkleTreeMmcs;
// use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
    CompressionFunctionFromHasher, MultiField32PaddingFreeSponge, SerializingHasher32,
};
use p3_symmetric::{Hash, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as ark_FpBN256,
    poseidon2::poseidon2_instance_bn256::RC3,
};

pub(crate) type Val = BabyBear;
pub(crate) type Challenge = BinomialExtensionField<Val, 4>;
pub(crate) type ByteHash = Keccak256Hash;
pub(crate) type FieldHash = SerializingHasher32<ByteHash>;
pub(crate) type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;
pub(crate) type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
pub(crate) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub(crate) type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
// pub(crate) type Pcs = CirclePcs<Val, ValMmcs>;
pub type Dft = Radix2DitParallel;
pub(crate) type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub const DIGEST_SIZE: usize = 1;

pub const OUTER_MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const OUTER_MULTI_FIELD_CHALLENGER_RATE: usize = 2;
pub const OUTER_MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

pub type OuterChallenge = BinomialExtensionField<Val, 4>;
pub type OuterPerm = Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
// pub type OuterPerm = Poseidon2Bn254<3>;
// pub type OuterPerm = p3_poseidon2::Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
pub type OuterHash = MultiField32PaddingFreeSponge<Val, Bn254Fr, OuterPerm, 3, 16, DIGEST_SIZE>;
pub type OuterDigestHash = Hash<Val, Bn254Fr, DIGEST_SIZE>;
pub type OuterDigest = [Bn254Fr; DIGEST_SIZE];
pub type OuterCompress = TruncatedPermutation<OuterPerm, 2, 1, 3>;
pub type OuterValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, OuterHash, OuterCompress, 1>;
pub type OuterChallengeMmcs = ExtensionMmcs<Val, OuterChallenge, OuterValMmcs>;
pub type OuterDft = Radix2DitParallel;
pub type OuterChallenger = MultiField32Challenger<
    Val,
    Bn254Fr,
    OuterPerm,
    OUTER_MULTI_FIELD_CHALLENGER_WIDTH,
    OUTER_MULTI_FIELD_CHALLENGER_RATE,
>;
pub type OuterPcs = TwoAdicFriPcs<Val, OuterDft, OuterValMmcs, OuterChallengeMmcs>;

pub(crate) type BabyBearKeccak = StarkConfig<Pcs, Challenge, Challenger>;
pub(crate) type BabyBearPoseidon2 = StarkConfig<OuterPcs, Challenge, OuterChallenger>;

// 1 instr cnt + 10 ops flags + 8 arg1 + 8 arg2 + 8 res + 7 carry
pub(crate) const BIN_OP_ROW_SIZE: usize = 42;
pub(crate) const WORD_SIZE: usize = 8;
pub(crate) const CARRY: usize = 7;
pub(crate) const LEFT_ARG: usize = 11;
pub(crate) const RIGHT_ARG: usize = 19;
pub(crate) const RESULT: usize = 27;
pub(crate) const CARRY_START: usize = 35;

pub fn default_fri_config() -> FriConfig<ChallengeMmcs> {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});
    let compress = MyCompress::new(byte_hash.clone());
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let num_queries = match std::env::var("FRI_QUERIES") {
        Ok(value) => value.parse().unwrap(),
        Err(_) => 100,
    };
    FriConfig {
        log_blowup: 1,
        num_queries,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}
pub fn default_stark_config() -> BabyBearKeccak {
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});
    let compress = MyCompress::new(byte_hash.clone());
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let fri_config = default_fri_config();
    let dft = Dft {};
    let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
    BabyBearKeccak::new(pcs)
}

fn bn254_from_ark_ff(input: ark_FpBN256) -> Bn254Fr {
    let bytes = input.into_bigint().to_bytes_le();

    let mut res = <FFBn254Fr as ff::PrimeField>::Repr::default();

    for (i, digit) in res.0.as_mut().iter_mut().enumerate() {
        *digit = bytes[i];
    }

    use ff::PrimeField;
    let value = FFBn254Fr::from_repr(res);

    if value.is_some().into() {
        Bn254Fr {
            value: value.unwrap(),
        }
    } else {
        panic!("Invalid field element")
    }
}

pub fn bn254_poseidon2_rc3() -> Vec<[Bn254Fr; 3]> {
    RC3.iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(bn254_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect()
}

pub fn outer_perm() -> OuterPerm {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;
    let mut round_constants = bn254_poseidon2_rc3();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = round_constants;
    OuterPerm::new(
        ROUNDS_F,
        external_round_constants,
        Poseidon2ExternalMatrixGeneral,
        ROUNDS_P,
        internal_round_constants,
        DiffusionMatrixBN254,
    )
}

pub fn outer_fri_config() -> FriConfig<OuterChallengeMmcs> {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let challenge_mmcs = OuterChallengeMmcs::new(OuterValMmcs::new(hash, compress));
    let num_queries =
        match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 25,
    };
    FriConfig { log_blowup: 4, num_queries, proof_of_work_bits: 16, mmcs: challenge_mmcs }
}
pub fn wrap_stark_config() -> BabyBearPoseidon2 {
    let perm = outer_perm();
    let hash = OuterHash::new(perm.clone()).unwrap();
    let compress = OuterCompress::new(perm.clone());
    let val_mmcs = OuterValMmcs::new(hash, compress);
    let dft = OuterDft {};
    let fri_config = outer_fri_config();
    let pcs = OuterPcs::new(27, dft, val_mmcs, fri_config);
    BabyBearPoseidon2::new(pcs)
}
