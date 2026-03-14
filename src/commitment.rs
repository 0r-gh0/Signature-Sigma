use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};

use crate::params::PublicParams;

pub struct PedersenCommitment(pub G1Affine);

/// Compute Com = m·g1 + r·g2.  Infallible.
pub fn commit(params: &PublicParams, m: Fr, r: Fr) -> PedersenCommitment {
    let point: G1Affine =
        (params.g1.into_group() * m + params.g2.into_group() * r).into_affine();
    PedersenCommitment(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::CurveGroup;
    use ark_ff::{UniformRand, Zero};
    use crate::params::setup;
    use crate::bbs::keygen;

    fn make_params() -> crate::params::PublicParams {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        setup(kp.pk).unwrap()
    }

    #[test]
    fn test_commit_known_values() {
        let params = make_params();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com = commit(&params, m, r);
        let expected: ark_bls12_381::G1Affine =
            (params.g1.into_group() * m + params.g2.into_group() * r).into_affine();
        assert_eq!(com.0, expected);
    }

    #[test]
    fn test_commit_zero_blinding() {
        let params = make_params();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let com = commit(&params, m, Fr::zero());
        let expected: ark_bls12_381::G1Affine =
            (params.g1.into_group() * m).into_affine();
        assert_eq!(com.0, expected);
    }
}
