use sigma::*;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_ec::AffineRepr;

fn setup_scenario() -> (PublicParams, Fr, Fr, BbsSignature, PedersenCommitment) {
    let g3 = ark_bls12_381::G2Affine::generator();
    let kp = keygen(&g3).expect("keygen failed");
    let params = setup(kp.pk).expect("setup failed");
    let mut rng = ark_std::test_rng();
    let m = Fr::rand(&mut rng);
    let r = Fr::rand(&mut rng);
    let sig = sign(&params, &kp.sk, m).expect("sign failed");
    let com = commit(&params, m, r);
    (params, m, r, sig, com)
}

// ── Happy path ─────────────────────────────────────────────────────────────────

#[test]
fn test_full_happy_path() {
    let (params, m, r, sig, com) = setup_scenario();
    let proof = prove(&params, &sig, &com, m, r)
        .expect("prove() failed on valid inputs");
    verify(&params, &com, &proof)
        .expect("verify() failed on valid proof");
}

#[test]
fn test_fresh_proof_each_run_still_verifies() {
    let (params, m, r, sig, com) = setup_scenario();
    for _ in 0..3 {
        let proof = prove(&params, &sig, &com, m, r).expect("prove failed");
        verify(&params, &com, &proof).expect("verify failed");
    }
}

// ── Negative: tampered z_* scalars ────────────────────────────────────────────

#[test]
fn test_flip_z_m_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_m = -proof.z_m;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

#[test]
fn test_flip_z_r_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_r = -proof.z_r;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

#[test]
fn test_flip_z_e_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_e = -proof.z_e;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

#[test]
fn test_flip_z_r2_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_r2 = -proof.z_r2;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

#[test]
fn test_flip_z_r3_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_r3 = -proof.z_r3;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

#[test]
fn test_flip_z_sprime_fails_verification() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.z_sprime = -proof.z_sprime;
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(_))
    ));
}

// ── Negative: wrong commitment ─────────────────────────────────────────────────

#[test]
fn test_wrong_com_different_m_fails_eq1() {
    let (params, m, r, sig, com) = setup_scenario();
    let proof = prove(&params, &sig, &com, m, r).unwrap();
    // Fiat-Shamir recomputes c using wrong_com; pairing doesn't involve Com so Eq1 fails first
    let mut rng = ark_std::rand::rngs::OsRng;
    let wrong_com = commit(&params, Fr::rand(&mut rng), r);
    assert!(matches!(
        verify(&params, &wrong_com, &proof),
        Err(SigmaError::VerificationFailed(2))
    ));
}

// ── Negative: tampered group elements ─────────────────────────────────────────

#[test]
fn test_tampered_a_bar_fails_pairing() {
    let (params, m, r, sig, com) = setup_scenario();
    let mut proof = prove(&params, &sig, &com, m, r).unwrap();
    proof.a_bar = ark_bls12_381::G1Affine::generator();
    assert!(matches!(
        verify(&params, &com, &proof),
        Err(SigmaError::VerificationFailed(1))
    ));
}

// ── Negative: zero A in signature passed to prove() ───────────────────────────

#[test]
fn test_zero_a_in_sig_prove_fails() {
    let (params, m, r, mut sig, com) = setup_scenario();
    sig.a = ark_bls12_381::G1Affine::zero();
    assert!(matches!(
        prove(&params, &sig, &com, m, r),
        Err(SigmaError::ProvingError(_))
    ));
}
