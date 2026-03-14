use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero, Field};
use rand::rngs::OsRng;

use crate::bbs::BbsSignature;
use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::hash::fiat_shamir_challenge;
use crate::params::PublicParams;
use crate::proof::{Proof, ProverSecrets};

/// Produce a non-interactive Sigma proof.
///
/// Proves: the message `m` inside `com` is correctly BBS+-signed under `params.pk`,
/// without revealing `m`, `sig`, or `r`.
pub fn prove(
    params: &PublicParams,
    sig:    &BbsSignature,
    com:    &PedersenCommitment,
    m:      Fr,
    r:      Fr,
) -> Result<Proof, SigmaError> {
    // Guard: m/r must be consistent with commitment
    let expected_com: G1Affine =
        (params.g1.into_group() * m + params.g2.into_group() * r).into_affine();
    if expected_com != com.0 {
        return Err(SigmaError::ProvingError(
            "m/r inconsistent with commitment".to_string()
        ));
    }

    let mut rng = OsRng;

    // Rejection-sample r1 != 0
    let r1 = loop {
        let x = Fr::rand(&mut rng);
        if !x.is_zero() { break x; }
    };

    // Compute A_prime = r1·A immediately; check for identity
    let a_prime_proj = sig.a.into_group() * r1;
    let a_prime: G1Affine = a_prime_proj.into_affine();
    if a_prime.is_zero() {
        return Err(SigmaError::ProvingError(
            "A_prime is the identity — invalid or corrupt signature".to_string()
        ));
    }

    // Rejection-sample r2 != 0
    let r2 = loop {
        let x = Fr::rand(&mut rng);
        if !x.is_zero() { break x; }
    };

    // r3 = r1⁻¹ (safe: r1 != 0)
    let r3 = r1.inverse().ok_or_else(|| {
        SigmaError::ProvingError("r1 has no inverse (unreachable)".to_string())
    })?;

    // Recompute B = s·h0 + m·h1 + g1
    let b_proj = params.h0.into_group() * sig.s
        + params.h1.into_group() * m
        + params.g1.into_group();

    // A_bar = r1·B - e·A_prime
    let a_bar: G1Affine = (b_proj * r1 - a_prime_proj * sig.e).into_affine();
    // D = r1·B - r2·h0
    let d: G1Affine = (b_proj * r1 - params.h0.into_group() * r2).into_affine();
    // s_prime = s - r2·r3
    let s_prime = sig.s - r2 * r3;

    // Commit phase — sample 6 blinding scalars
    let temp_m      = Fr::rand(&mut rng);
    let temp_r      = Fr::rand(&mut rng);
    let temp_e      = Fr::rand(&mut rng);
    let temp_r2     = Fr::rand(&mut rng);
    let temp_r3     = Fr::rand(&mut rng);
    let temp_sprime = Fr::rand(&mut rng);

    // R = temp_m·g1 + temp_r·g2
    let cap_r: G1Affine =
        (params.g1.into_group() * temp_m + params.g2.into_group() * temp_r).into_affine();
    // T1 = (-temp_e)·A_prime + temp_r2·h0
    let t1: G1Affine =
        (a_prime_proj * (-temp_e) + params.h0.into_group() * temp_r2).into_affine();
    // T2 = (-temp_r3)·D + temp_sprime·h0 + temp_m·h1
    let d_proj = d.into_group();
    let t2: G1Affine =
        (d_proj * (-temp_r3)
            + params.h0.into_group() * temp_sprime
            + params.h1.into_group() * temp_m)
        .into_affine();

    // Fiat-Shamir challenge
    let c = fiat_shamir_challenge(params, com, a_prime, a_bar, d, cap_r, t1, t2)?;

    // Response phase (ProverSecrets zeroized on drop)
    let secrets = ProverSecrets {
        r1, r2, r3, s_prime,
        temp_m, temp_r, temp_e, temp_r2, temp_r3,
        temp_sprime,
    };

    let z_m      = secrets.temp_m      + c * m;
    let z_r      = secrets.temp_r      + c * r;
    let z_e      = secrets.temp_e      + c * sig.e;
    let z_r2     = secrets.temp_r2     + c * secrets.r2;
    let z_r3     = secrets.temp_r3     + c * secrets.r3;  // no sign flip — spec §4.3
    let z_sprime = secrets.temp_sprime + c * secrets.s_prime;

    drop(secrets); // explicitly triggers zeroize

    Ok(Proof { a_prime, a_bar, d, cap_r, t1, t2, z_m, z_r, z_e, z_r2, z_r3, z_sprime })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit};

    fn make_scenario() -> (PublicParams, Fr, Fr, BbsSignature, PedersenCommitment) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let sig = sign(&params, &kp.sk, m).unwrap();
        let com = commit(&params, m, r);
        (params, m, r, sig, com)
    }

    #[test]
    fn test_prove_returns_proof() {
        let (params, m, r, sig, com) = make_scenario();
        let result = prove(&params, &sig, &com, m, r);
        assert!(result.is_ok(), "prove() failed: {:?}", result.err());
    }

    #[test]
    fn test_prove_wrong_commitment_fails() {
        let (params, m, r, sig, _) = make_scenario();
        // Use OsRng to guarantee a different m_wrong (avoids deterministic-rng collision)
        let m_wrong = loop {
            let x = Fr::rand(&mut OsRng);
            if x != m { break x; }
        };
        let wrong_com = commit(&params, m_wrong, r);
        let result = prove(&params, &sig, &wrong_com, m, r);
        assert!(matches!(result, Err(SigmaError::ProvingError(_))));
    }

    #[test]
    fn test_prove_zero_a_fails() {
        let (params, m, r, mut sig, com) = make_scenario();
        sig.a = G1Affine::zero();
        let result = prove(&params, &sig, &com, m, r);
        assert!(matches!(result, Err(SigmaError::ProvingError(_))));
    }
}
