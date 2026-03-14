use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::hash::fiat_shamir_challenge;
use crate::params::PublicParams;
use crate::proof::Proof;

/// Verify a Sigma proof.
///
/// # Errors
/// - `InvalidParams` if `params.pk == G2::zero()`
/// - `VerificationFailed(0)` if a_prime, a_bar, or d is the identity
/// - `VerificationFailed(1)` pairing check
/// - `VerificationFailed(2)` Eq1
/// - `VerificationFailed(3)` Eq2
/// - `VerificationFailed(4)` Eq3
pub fn verify(
    params: &PublicParams,
    com:    &PedersenCommitment,
    proof:  &Proof,
) -> Result<(), SigmaError> {
    // Guard: valid public key
    if params.pk.is_zero() {
        return Err(SigmaError::InvalidParams);
    }

    // Soundness pre-checks (all three identity checks under code 0)
    if proof.a_prime.is_zero() || proof.a_bar.is_zero() || proof.d.is_zero() {
        return Err(SigmaError::VerificationFailed(0));
    }

    // Recompute challenge c
    let c = fiat_shamir_challenge(
        params, com,
        proof.a_prime, proof.a_bar, proof.d,
        proof.cap_r, proof.t1, proof.t2,
    )?;

    // Pairing check: e(a_prime, pk) == e(a_bar, g3)
    let lhs = Bls12_381::pairing(proof.a_prime, params.pk);
    let rhs = Bls12_381::pairing(proof.a_bar, params.g3);
    if lhs != rhs {
        return Err(SigmaError::VerificationFailed(1));
    }

    // Eq1: z_m·g1 + z_r·g2 == cap_r + c·Com
    {
        let lhs: G1Affine =
            (params.g1.into_group() * proof.z_m + params.g2.into_group() * proof.z_r)
            .into_affine();
        let rhs: G1Affine =
            (proof.cap_r.into_group() + com.0.into_group() * c).into_affine();
        if lhs != rhs {
            return Err(SigmaError::VerificationFailed(2));
        }
    }

    // Eq2: (-z_e)·a_prime + z_r2·h0 == t1 + c·(a_bar - d)
    {
        let lhs: G1Affine =
            (proof.a_prime.into_group() * (-proof.z_e)
                + params.h0.into_group() * proof.z_r2)
            .into_affine();
        let a_bar_minus_d = proof.a_bar.into_group() - proof.d.into_group();
        let rhs: G1Affine = (proof.t1.into_group() + a_bar_minus_d * c).into_affine();
        if lhs != rhs {
            return Err(SigmaError::VerificationFailed(3));
        }
    }

    // Eq3: (-z_r3)·d + z_sprime·h0 + z_m·h1 == t2 - c·g1
    {
        let lhs: G1Affine =
            (proof.d.into_group() * (-proof.z_r3)
                + params.h0.into_group() * proof.z_sprime
                + params.h1.into_group() * proof.z_m)
            .into_affine();
        let rhs: G1Affine =
            (proof.t2.into_group() - params.g1.into_group() * c).into_affine();
        if lhs != rhs {
            return Err(SigmaError::VerificationFailed(4));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit, prover::prove};

    fn make_proof() -> (PublicParams, PedersenCommitment, Proof) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let sig = sign(&params, &kp.sk, m).unwrap();
        let com = commit(&params, m, r);
        let proof = prove(&params, &sig, &com, m, r).unwrap();
        (params, com, proof)
    }

    #[test]
    fn test_verify_valid_proof() {
        let (params, com, proof) = make_proof();
        assert!(verify(&params, &com, &proof).is_ok());
    }

    #[test]
    fn test_verify_zero_pk_fails() {
        let (mut params, com, proof) = make_proof();
        params.pk = ark_bls12_381::G2Affine::zero();
        assert!(matches!(verify(&params, &com, &proof), Err(SigmaError::InvalidParams)));
    }

    #[test]
    fn test_verify_zero_a_prime_fails() {
        let (params, com, mut proof) = make_proof();
        proof.a_prime = ark_bls12_381::G1Affine::zero();
        assert!(matches!(
            verify(&params, &com, &proof),
            Err(SigmaError::VerificationFailed(0))
        ));
    }

    #[test]
    fn test_verify_tampered_a_bar_fails() {
        let (params, com, mut proof) = make_proof();
        proof.a_bar = ark_bls12_381::G1Affine::generator();
        assert!(matches!(
            verify(&params, &com, &proof),
            Err(SigmaError::VerificationFailed(1))
        ));
    }

    #[test]
    fn test_verify_wrong_com_fails() {
        let (params, _, proof) = make_proof();
        let wrong_com = commit(&params, Fr::rand(&mut ark_std::test_rng()), Fr::rand(&mut ark_std::test_rng()));
        assert!(matches!(
            verify(&params, &wrong_com, &proof),
            Err(SigmaError::VerificationFailed(_))
        ));
    }

    #[test]
    fn test_verify_flipped_z_m_fails() {
        let (params, com, mut proof) = make_proof();
        proof.z_m = -proof.z_m;
        assert!(matches!(
            verify(&params, &com, &proof),
            Err(SigmaError::VerificationFailed(_))
        ));
    }
}
