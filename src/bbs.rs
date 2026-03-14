use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero, Field};
use rand::rngs::OsRng;

use crate::errors::SigmaError;
use crate::params::PublicParams;

pub struct SecretKey(pub Fr);

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: G2Affine,
}

/// BBS+ signature. B is NOT stored; reconstruct as s·h0 + m·h1 + g1.
pub struct BbsSignature {
    pub a: G1Affine,
    pub e: Fr,
    pub s: Fr,
}

/// Sample x ← Fr \ {0}, compute pk = x·g3.
pub fn keygen(g3: &G2Affine) -> Result<KeyPair, SigmaError> {
    let mut rng = OsRng;
    let sk = loop {
        let x = Fr::rand(&mut rng);
        if !x.is_zero() {
            break x;
        }
    };
    let pk: G2Affine = (*g3 * sk).into_affine();
    Ok(KeyPair { sk: SecretKey(sk), pk })
}

/// Sign message m under secret key sk.
/// Guards: sk != 0; resamples e if sk + e == 0.
/// debug_assert: (sk + e)·A == B in debug builds.
pub fn sign(
    params: &PublicParams,
    sk: &SecretKey,
    m: Fr,
) -> Result<BbsSignature, SigmaError> {
    if sk.0.is_zero() {
        return Err(SigmaError::SigningError("secret key is zero".to_string()));
    }

    let mut rng = OsRng;

    let e = loop {
        let e_candidate = Fr::rand(&mut rng);
        if !(sk.0 + e_candidate).is_zero() {
            break e_candidate;
        }
    };
    let s = Fr::rand(&mut rng);

    // B = s·h0 + m·h1 + g1
    let b_proj = params.h0.into_group() * s
        + params.h1.into_group() * m
        + params.g1.into_group();
    let b: G1Affine = b_proj.into_affine();

    debug_assert!(!b.is_zero(), "B should not be the identity");

    // A = B / (x + e)
    let x_plus_e = sk.0 + e;
    let x_plus_e_inv = x_plus_e.inverse()
        .ok_or_else(|| SigmaError::SigningError("x + e has no inverse".to_string()))?;
    let a: G1Affine = (b_proj * x_plus_e_inv).into_affine();

    debug_assert_eq!(
        (a.into_group() * x_plus_e).into_affine(),
        b,
        "sign: sanity check (x+e)·A == B failed"
    );

    Ok(BbsSignature { a, e, s })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
    use ark_ff::{UniformRand, Zero};
    use crate::params::setup;

    fn make_params_and_kp() -> (PublicParams, KeyPair) {
        let g3 = G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        (params, kp)
    }

    #[test]
    fn test_keygen_nonzero_sk() {
        let g3 = G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        assert!(!kp.sk.0.is_zero());
    }

    #[test]
    fn test_keygen_pk_consistent() {
        let g3 = G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let expected_pk: G2Affine = (g3 * kp.sk.0).into_affine();
        assert_eq!(kp.pk, expected_pk);
    }

    #[test]
    fn test_sign_pairing_check() {
        let (params, kp) = make_params_and_kp();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let sig = sign(&params, &kp.sk, m).unwrap();

        let b_proj = params.h0.into_group() * sig.s
            + params.h1.into_group() * m
            + params.g1.into_group();
        let b: G1Affine = b_proj.into_affine();

        let pk_plus_e_g3: G2Affine =
            (params.pk.into_group() + params.g3 * sig.e).into_affine();
        let lhs = Bls12_381::pairing(sig.a, pk_plus_e_g3);
        let rhs = Bls12_381::pairing(b, params.g3);
        assert_eq!(lhs, rhs, "BBS+ pairing check failed");
    }

    #[test]
    fn test_sign_zero_sk_fails() {
        let g3 = G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let zero_sk = SecretKey(Fr::zero());
        let result = sign(&params, &zero_sk, Fr::rand(&mut ark_std::test_rng()));
        assert!(matches!(result, Err(SigmaError::SigningError(_))));
    }
}
