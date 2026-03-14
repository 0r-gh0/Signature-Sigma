use ark_bls12_381::{Fr, G1Affine};
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::params::PublicParams;

const DST: &[u8] = b"SIGMA-BBS+-FIAT-SHAMIR-BLS12381";

/// Compute the Fiat-Shamir challenge c.
///
/// Input layout (720 bytes):
///   g1 g2 [2×48] | g3 [96] | h0 h1 [2×48] | PK [96]  → 384 bytes static
///   | Com A_prime A_bar D R T1 T2 [7×48]              → 336 bytes
///
/// `com` is the caller-supplied Pedersen commitment — NOT a Proof field.
#[allow(clippy::too_many_arguments)]
pub fn fiat_shamir_challenge(
    params:  &PublicParams,
    com:     &PedersenCommitment,
    a_prime: G1Affine,
    a_bar:   G1Affine,
    d:       G1Affine,
    cap_r:   G1Affine,
    t1:      G1Affine,
    t2:      G1Affine,
) -> Result<Fr, SigmaError> {
    let mut buf = Vec::with_capacity(720);

    // Static params: 4×G1 + 2×G2 = 4×48 + 2×96 = 384 bytes
    params.g1.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    params.g2.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    params.g3.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    params.h0.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    params.h1.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    params.pk.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;

    // 7×G1 = 336 bytes: Com, A_prime, A_bar, D, R, T1, T2
    com.0.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    a_prime.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    a_bar.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    d.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    cap_r.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    t1.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;
    t2.serialize_compressed(&mut buf)
        .map_err(|e| SigmaError::HashError(e.to_string()))?;

    debug_assert_eq!(buf.len(), 720, "hash input must be exactly 720 bytes");

    // RFC 9380 hash_to_field: L=48 for Fr (255-bit scalar field, k=128)
    let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fr>>::new(DST);
    let fields: Vec<Fr> = hasher.hash_to_field(&buf, 1);
    Ok(fields[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use crate::params::setup;
    use crate::bbs::keygen;
    use crate::commitment::commit;

    fn make_params() -> crate::params::PublicParams {
        let g3 = G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        setup(kp.pk).unwrap()
    }

    #[test]
    fn test_challenge_is_deterministic() {
        let params = make_params();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com = commit(&params, m, r);
        let zero_g1 = G1Affine::zero();

        let c1 = fiat_shamir_challenge(&params, &com, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        let c2 = fiat_shamir_challenge(&params, &com, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_challenge_changes_with_different_input() {
        let params = make_params();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com1 = commit(&params, m, r);
        let com2 = commit(&params, Fr::rand(&mut rng), r);
        let zero_g1 = G1Affine::zero();

        let c1 = fiat_shamir_challenge(&params, &com1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        let c2 = fiat_shamir_challenge(&params, &com2, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        assert_ne!(c1, c2);
    }
}
