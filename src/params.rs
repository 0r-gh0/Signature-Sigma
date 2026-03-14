use ark_bls12_381::{G1Affine, G1Projective, G2Affine, g1::Config as G1Config};
use ark_ec::hashing::{
    HashToCurve,
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
};
use ark_ff::fields::field_hashers::DefaultFieldHasher;
use sha2::Sha256;

use crate::errors::SigmaError;

pub struct PublicParams {
    pub g1: G1Affine,
    pub g2: G1Affine,
    pub g3: G2Affine,
    pub h0: G1Affine,
    pub h1: G1Affine,
    pub pk: G2Affine,
}

type G1Hasher = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256>,
    WBMap<G1Config>,
>;

fn hash_to_g1(dst: &[u8]) -> Result<G1Affine, SigmaError> {
    let hasher = G1Hasher::new(dst)
        .map_err(|e| SigmaError::HashError(format!("{e:?}")))?;
    hasher.hash(b"")
        .map_err(|e| SigmaError::HashError(format!("{e:?}")))
}

/// Construct PublicParams from a caller-supplied BBS+ public key.
/// G1 generators via hash_to_curve (RFC 9380), g3 = standard G2 generator.
/// Returns `InvalidParams` if `pk == G2::zero()`.
pub fn setup(pk: G2Affine) -> Result<PublicParams, SigmaError> {
    use ark_ec::AffineRepr;
    if pk.is_zero() {
        return Err(SigmaError::InvalidParams);
    }

    let g1 = hash_to_g1(b"SIGMA-BBS-G1-BASE-BLS12381")?;
    let g2 = hash_to_g1(b"SIGMA-BBS-G1-BIND-BLS12381")?;
    let h0 = hash_to_g1(b"SIGMA-BBS-H0-BLS12381")?;
    let h1 = hash_to_g1(b"SIGMA-BBS-H1-BLS12381")?;
    let g3 = G2Affine::generator();

    Ok(PublicParams { g1, g2, g3, h0, h1, pk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;

    fn make_pk() -> G2Affine {
        let g3 = G2Affine::generator();
        let mut rng = ark_std::test_rng();
        let x = Fr::rand(&mut rng);
        (g3 * x).into()
    }

    #[test]
    fn test_setup_valid() {
        let pk = make_pk();
        let params = setup(pk).unwrap();
        assert!(!params.g1.is_zero());
        assert!(!params.g2.is_zero());
        assert!(!params.h0.is_zero());
        assert!(!params.h1.is_zero());
        assert_ne!(params.g1, params.g2);
        assert_ne!(params.g1, params.h0);
        assert_ne!(params.g1, params.h1);
        assert_eq!(params.pk, pk);
    }

    #[test]
    fn test_setup_zero_pk_fails() {
        let result = setup(G2Affine::zero());
        assert!(matches!(result, Err(crate::errors::SigmaError::InvalidParams)));
    }

    #[test]
    fn test_setup_deterministic() {
        let pk = make_pk();
        let p1 = setup(pk).unwrap();
        let p2 = setup(pk).unwrap();
        assert_eq!(p1.g1, p2.g1);
        assert_eq!(p1.g2, p2.g2);
        assert_eq!(p1.h0, p2.h0);
        assert_eq!(p1.h1, p2.h1);
    }
}
