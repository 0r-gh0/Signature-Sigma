# Sigma Protocol over BBS+ Signatures — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a non-interactive zero-knowledge Sigma Protocol in Rust that proves knowledge of a BBS+-signed message inside a Pedersen commitment, without revealing the message, signature, or blinding factors.

**Architecture:** Single Rust library crate at `/home/argha/sigma/` with 8 focused source modules: errors → params → bbs → commitment → proof → hash → prover → verifier. Each module has one clear responsibility; `lib.rs` re-exports the public API. TDD throughout — every implementation is preceded by a failing test.

**Tech Stack:** Rust (edition 2021), ark-bls12-381 0.4, ark-ec 0.4, ark-ff 0.4, ark-serialize 0.4, thiserror 1, sha2 0.10, zeroize 1 (derive feature).

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `Cargo.toml` | Crate manifest + all dependencies |
| Create | `src/lib.rs` | Public API re-exports |
| Create | `src/errors.rs` | `SigmaError` enum |
| Create | `src/params.rs` | `PublicParams`, `setup()` |
| Create | `src/bbs.rs` | `SecretKey`, `KeyPair`, `BbsSignature`, `keygen()`, `sign()` |
| Create | `src/commitment.rs` | `PedersenCommitment`, `commit()` |
| Create | `src/proof.rs` | `Proof` (public), `ProverSecrets` (crate-internal) |
| Create | `src/hash.rs` | `fiat_shamir_challenge()` |
| Create | `src/prover.rs` | `prove()` |
| Create | `src/verifier.rs` | `verify()` |
| Create | `tests/integration.rs` | Full end-to-end integration tests |

---

## Chunk 1: Project Scaffolding + Errors + Params + BBS

### Task 1: Project scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs` (stub — just `mod` declarations)
- Create: `src/errors.rs`
- Create: `src/params.rs`
- Create: `src/bbs.rs`
- Create: `src/commitment.rs`
- Create: `src/proof.rs`
- Create: `src/hash.rs`
- Create: `src/prover.rs`
- Create: `src/verifier.rs`

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "sigma"
version = "0.1.0"
edition = "2021"

[dependencies]
ark-bls12-381 = "0.4"
ark-ec        = "0.4"
ark-ff        = "0.4"
ark-std       = "0.4"
ark-serialize = "0.4"
thiserror     = "1"
sha2          = "0.10"
zeroize       = { version = "1", features = ["derive"] }

[dev-dependencies]
ark-std = { version = "0.4", features = ["std"] }
```

- [ ] **Step 2: Create stub `src/lib.rs`**

```rust
pub mod errors;
pub mod params;
pub mod bbs;
pub mod commitment;
pub mod proof;
pub mod hash;
pub mod prover;
pub mod verifier;

pub use crate::errors::SigmaError;
pub use crate::params::{PublicParams, setup};
pub use crate::bbs::{SecretKey, KeyPair, BbsSignature, keygen, sign};
pub use crate::commitment::{PedersenCommitment, commit};
pub use crate::proof::Proof;
pub use crate::prover::prove;
pub use crate::verifier::verify;
```

- [ ] **Step 3: Create empty stub files** (one-liner each so it compiles)

Create `src/errors.rs`:
```rust
// placeholder
```
Create `src/params.rs`, `src/bbs.rs`, `src/commitment.rs`, `src/proof.rs`, `src/hash.rs`, `src/prover.rs`, `src/verifier.rs` — each with just `// placeholder`.

- [ ] **Step 4: Verify `cargo check` passes with stubs**

Run: `cd /home/argha/sigma && cargo check 2>&1 | head -30`

Expected: compile errors about missing items (because lib.rs uses them), but no Cargo.toml errors.

> **Note:** The stubs above are just `// placeholder` — the re-exports in `lib.rs` will fail. That's fine. We build up modules one by one.

---

### Task 2: `errors.rs`

**Files:**
- Modify: `src/errors.rs`
- Modify: `src/lib.rs` (fix re-exports as modules come online)

- [ ] **Step 1: Write the failing test**

Add to `src/errors.rs` (temporarily, for test-first approach):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = SigmaError::SigningError("test".to_string());
        assert!(e.to_string().contains("test"));

        let e = SigmaError::VerificationFailed(2);
        assert!(e.to_string().contains("2"));

        let e = SigmaError::InvalidParams;
        assert!(!e.to_string().is_empty());
    }
}
```

- [ ] **Step 2: Run test — verify it fails**

Run: `cd /home/argha/sigma && cargo test -p sigma test_error_display 2>&1 | tail -10`

Expected: FAIL — `SigmaError` not defined.

- [ ] **Step 3: Implement `errors.rs`**

```rust
#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    #[error("BBS+ signing failed: {0}")]
    SigningError(String),

    #[error("Invalid public parameters")]
    InvalidParams,

    #[error("Proving failed: {0}")]
    ProvingError(String),

    #[error("Proof verification failed: check {0} did not hold")]
    VerificationFailed(u8),

    #[error("Hash to field error: {0}")]
    HashError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = SigmaError::SigningError("test".to_string());
        assert!(e.to_string().contains("test"));

        let e = SigmaError::VerificationFailed(2);
        assert!(e.to_string().contains("2"));

        let e = SigmaError::InvalidParams;
        assert!(!e.to_string().is_empty());
    }
}
```

- [ ] **Step 4: Run test — verify it passes**

Run: `cd /home/argha/sigma && cargo test errors::tests::test_error_display -- --nocapture 2>&1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git init && git add Cargo.toml src/
git commit -m "feat: scaffold crate and implement SigmaError"
```

---

### Task 3: `params.rs` — `PublicParams` and `setup()`

**Files:**
- Modify: `src/params.rs`

- [ ] **Step 1: Write the failing test**

```rust
// In src/params.rs (at bottom of file)
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{G2Affine, Fr};
    use ark_ec::AffineRepr;

    fn make_pk() -> G2Affine {
        let g3 = G2Affine::generator();
        use ark_ff::UniformRand;
        let mut rng = ark_std::test_rng();
        let x = Fr::rand(&mut rng);
        (g3 * x).into()
    }

    #[test]
    fn test_setup_valid() {
        let pk = make_pk();
        let params = setup(pk).unwrap();
        // Generators must be non-zero and distinct
        use ark_ec::AffineRepr;
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
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test params::tests 2>&1 | tail -20`

Expected: FAIL — `setup` and `PublicParams` not defined.

- [ ] **Step 3: Implement `params.rs`**

```rust
use ark_bls12_381::{G1Affine, G2Affine, g1::Config as G1Config};
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
    G1Config,
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
///
/// G1 generators are produced via hash_to_curve (RFC 9380) from distinct
/// domain-separated seeds ensuring no known discrete-log relation between them.
/// g3 is the standard BLS12-381 G2 generator.
///
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
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test params::tests 2>&1`

Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/params.rs
git commit -m "feat: implement PublicParams and setup() with hash_to_curve generators"
```

---

### Task 4: `bbs.rs` — `keygen()` and `sign()`

**Files:**
- Modify: `src/bbs.rs`

- [ ] **Step 1: Write the failing test**

```rust
// In src/bbs.rs tests module:
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_ff::UniformRand;
    use crate::params::setup;

    fn make_params_and_kp() -> (crate::params::PublicParams, KeyPair) {
        let mut rng = ark_std::test_rng();
        // keygen needs g3 — get it from a dummy setup first, then real setup with pk
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        (params, kp)
    }

    #[test]
    fn test_keygen_nonzero_sk() {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        use ark_ff::Zero;
        assert_ne!(kp.sk.0, Fr::zero());
    }

    #[test]
    fn test_keygen_pk_consistent() {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        use ark_ec::CurveGroup;
        let expected_pk: ark_bls12_381::G2Affine = (g3 * kp.sk.0).into_affine();
        assert_eq!(kp.pk, expected_pk);
    }

    #[test]
    fn test_sign_pairing_check() {
        let (params, kp) = make_params_and_kp();
        let mut rng = ark_std::test_rng();
        let m = Fr::rand(&mut rng);
        let sig = sign(&params, &kp.sk, m).unwrap();

        // Recompute B
        use ark_ec::CurveGroup;
        let b_proj = params.h0.into_group() * sig.s
            + params.h1.into_group() * m
            + params.g1.into_group();
        let b: G1Affine = b_proj.into_affine();

        // e(A, PK + e·g3) == e(B, g3)
        let pk_plus_e_g3: ark_bls12_381::G2Affine =
            (params.pk.into_group() + params.g3 * sig.e).into_affine();
        let lhs = Bls12_381::pairing(sig.a, pk_plus_e_g3);
        let rhs = Bls12_381::pairing(b, params.g3);
        assert_eq!(lhs, rhs, "BBS+ pairing check failed");
    }

    #[test]
    fn test_sign_zero_sk_fails() {
        let g3 = ark_bls12_381::G2Affine::generator();
        let zero_pk = ark_bls12_381::G2Affine::zero();
        // Can't use setup with zero pk, so build params manually for this edge case
        // Just test SecretKey(zero) path
        let params_dummy = {
            let kp = keygen(&g3).unwrap();
            setup(kp.pk).unwrap()
        };
        use ark_ff::Zero;
        let zero_sk = SecretKey(Fr::zero());
        let result = sign(&params_dummy, &zero_sk, Fr::rand(&mut ark_std::test_rng()));
        assert!(matches!(result, Err(crate::errors::SigmaError::SigningError(_))));
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test bbs::tests 2>&1 | tail -20`

Expected: FAIL — `keygen`, `sign`, `SecretKey`, etc. not defined.

- [ ] **Step 3: Implement `bbs.rs`**

```rust
use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero, One};
use ark_std::rand::SeedableRng;

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
    let mut rng = ark_std::rand::rngs::OsRng;
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
///
/// Guards:
/// - sk.0 must be non-zero
/// - Resamples e if sk.0 + e == 0
/// - debug_assert! that (sk.0 + e)·A == B
pub fn sign(
    params: &PublicParams,
    sk: &SecretKey,
    m: Fr,
) -> Result<BbsSignature, SigmaError> {
    if sk.0.is_zero() {
        return Err(SigmaError::SigningError("secret key is zero".to_string()));
    }

    let mut rng = ark_std::rand::rngs::OsRng;

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

    // A = B / (x + e)  i.e. (x + e)·A = B
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
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use crate::params::setup;

    fn make_params_and_kp() -> (crate::params::PublicParams, KeyPair) {
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
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let result = sign(&params, &zero_sk, Fr::rand(&mut ark_std::rand::rngs::OsRng));
        assert!(matches!(result, Err(SigmaError::SigningError(_))));
    }
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test bbs::tests 2>&1`

Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/bbs.rs
git commit -m "feat: implement BBS+ keygen() and sign() with pairing-verified signatures"
```

---

## Chunk 2: Commitment + Proof Structs + Hash

### Task 5: `commitment.rs` — Pedersen commitment

**Files:**
- Modify: `src/commitment.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
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
        let mut rng = ark_std::rand::rngs::OsRng;
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com = commit(&params, m, r);

        // Verify manually: Com = m·g1 + r·g2
        let expected: ark_bls12_381::G1Affine =
            (params.g1.into_group() * m + params.g2.into_group() * r).into_affine();
        assert_eq!(com.0, expected);
    }

    #[test]
    fn test_commit_zero_blinding() {
        let params = make_params();
        let mut rng = ark_std::rand::rngs::OsRng;
        let m = Fr::rand(&mut rng);
        use ark_ff::Zero;
        let com = commit(&params, m, Fr::zero());
        let expected: ark_bls12_381::G1Affine = (params.g1.into_group() * m).into_affine();
        assert_eq!(com.0, expected);
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test commitment::tests 2>&1 | tail -10`

Expected: FAIL.

- [ ] **Step 3: Implement `commitment.rs`**

```rust
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
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let mut rng = ark_std::rand::rngs::OsRng;
        let m = Fr::rand(&mut rng);
        let com = commit(&params, m, Fr::zero());
        let expected: ark_bls12_381::G1Affine =
            (params.g1.into_group() * m).into_affine();
        assert_eq!(com.0, expected);
    }
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test commitment::tests 2>&1`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/commitment.rs
git commit -m "feat: implement Pedersen commit()"
```

---

### Task 6: `proof.rs` — `Proof` struct and `ProverSecrets`

**Files:**
- Modify: `src/proof.rs`

> **Note:** `ProverSecrets` is crate-internal (`pub(crate)`). It must implement `Zeroize` and `Drop` since `Fr` doesn't derive `Zeroize`. The `Proof` struct is public and has no sensitive data — no `Zeroize` needed on it.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ff::{UniformRand, Zero};

    #[test]
    fn test_proof_fields_accessible() {
        use ark_ec::AffineRepr;
        let zero = G1Affine::zero();
        use ark_ff::Zero;
        let p = Proof {
            a_prime: zero,
            a_bar: zero,
            d: zero,
            cap_r: zero,
            t1: zero,
            t2: zero,
            z_m: Fr::zero(),
            z_r: Fr::zero(),
            z_e: Fr::zero(),
            z_r2: Fr::zero(),
            z_r3: Fr::zero(),
            z_sprime: Fr::zero(),
        };
        assert_eq!(p.z_m, Fr::zero());
    }

    #[test]
    fn test_prover_secrets_zeroize() {
        use zeroize::Zeroize;
        let mut s = ProverSecrets {
            r1: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            r2: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            r3: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            s_prime: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_m: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_e: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r2: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r3: Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_sprime: Fr::rand(&mut ark_std::rand::rngs::OsRng),
        };
        s.zeroize();
        assert_eq!(s.r1, Fr::zero());
        assert_eq!(s.r2, Fr::zero());
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test proof::tests 2>&1 | tail -15`

Expected: FAIL — `Proof`, `ProverSecrets` not defined.

- [ ] **Step 3: Implement `proof.rs`**

```rust
use ark_bls12_381::{Fr, G1Affine};
use ark_ff::Zero;
use zeroize::Zeroize;

pub struct Proof {
    pub a_prime:  G1Affine,   // r1·A
    pub a_bar:    G1Affine,   // r1·B - e·A_prime  (= x·A_prime)
    pub d:        G1Affine,   // r1·B - r2·h0
    pub cap_r:    G1Affine,   // Pedersen blinding commitment R (the G1 point)
    pub t1:       G1Affine,
    pub t2:       G1Affine,
    pub z_m:      Fr,
    pub z_r:      Fr,
    pub z_e:      Fr,
    pub z_r2:     Fr,
    pub z_r3:     Fr,
    pub z_sprime: Fr,
}

/// Sensitive prover state. Zeroized on drop.
/// Never returned to caller — lives only inside prove().
pub(crate) struct ProverSecrets {
    pub r1:          Fr,
    pub r2:          Fr,
    pub r3:          Fr,       // = r1⁻¹
    pub s_prime:     Fr,       // = s - r2·r3
    pub temp_m:      Fr,
    pub temp_r:      Fr,
    pub temp_e:      Fr,
    pub temp_r2:     Fr,
    pub temp_r3:     Fr,
    pub temp_sprime: Fr,
}

impl Zeroize for ProverSecrets {
    fn zeroize(&mut self) {
        // Fr doesn't implement Zeroize, so we zero the raw memory manually
        // using volatile writes to prevent the optimizer from eliding them.
        let ptr = self as *mut ProverSecrets as *mut u8;
        let len = std::mem::size_of::<ProverSecrets>();
        for i in 0..len {
            // SAFETY: ptr is valid, in-bounds, and properly aligned as *mut u8
            unsafe { std::ptr::write_volatile(ptr.add(i), 0u8); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for ProverSecrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use zeroize::Zeroize;

    #[test]
    fn test_proof_fields_accessible() {
        let zero_g1 = G1Affine::zero();
        let p = Proof {
            a_prime: zero_g1,
            a_bar: zero_g1,
            d: zero_g1,
            cap_r: zero_g1,
            t1: zero_g1,
            t2: zero_g1,
            z_m: Fr::zero(),
            z_r: Fr::zero(),
            z_e: Fr::zero(),
            z_r2: Fr::zero(),
            z_r3: Fr::zero(),
            z_sprime: Fr::zero(),
        };
        assert_eq!(p.z_m, Fr::zero());
    }

    #[test]
    fn test_prover_secrets_zeroize() {
        let mut s = ProverSecrets {
            r1:          Fr::rand(&mut ark_std::rand::rngs::OsRng),
            r2:          Fr::rand(&mut ark_std::rand::rngs::OsRng),
            r3:          Fr::rand(&mut ark_std::rand::rngs::OsRng),
            s_prime:     Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_m:      Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r:      Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_e:      Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r2:     Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_r3:     Fr::rand(&mut ark_std::rand::rngs::OsRng),
            temp_sprime: Fr::rand(&mut ark_std::rand::rngs::OsRng),
        };
        s.zeroize();
        assert_eq!(s.r1, Fr::zero());
        assert_eq!(s.r2, Fr::zero());
    }
}
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test proof::tests 2>&1`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/proof.rs
git commit -m "feat: define Proof and ProverSecrets with zeroize-on-drop"
```

---

### Task 7: `hash.rs` — Fiat-Shamir challenge

**Files:**
- Modify: `src/hash.rs`

> **Critical:** Input is exactly 720 bytes. Order: g1 g2 g3 h0 h1 PK Com A_prime A_bar D R T1 T2.
> G1 compressed = 48 bytes; G2 compressed = 96 bytes.
> DST = `b"SIGMA-BBS+-FIAT-SHAMIR-BLS12381"` (31 bytes).
> `L = 48` (Fr, 255-bit field, k=128: ceil((255+128)/8)=48).
> Use `DefaultFieldHasher<Sha256, 128>` implementing `HashToField<Fr>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::Zero;
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
        use ark_ff::UniformRand;
        let params = make_params();
        let mut rng = ark_std::rand::rngs::OsRng;
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com = commit(&params, m, r);
        let zero_g1 = G1Affine::zero();

        let c1 = fiat_shamir_challenge(&params, &com, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        let c2 = fiat_shamir_challenge(&params, &com, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        assert_eq!(c1, c2, "challenge must be deterministic");
    }

    #[test]
    fn test_challenge_changes_with_different_input() {
        use ark_ff::UniformRand;
        let params = make_params();
        let mut rng = ark_std::rand::rngs::OsRng;
        let m = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let com1 = commit(&params, m, r);
        let com2 = commit(&params, Fr::rand(&mut rng), r);
        let zero_g1 = G1Affine::zero();

        let c1 = fiat_shamir_challenge(&params, &com1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        let c2 = fiat_shamir_challenge(&params, &com2, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1, zero_g1).unwrap();
        assert_ne!(c1, c2, "different inputs must produce different challenges");
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test hash::tests 2>&1 | tail -10`

Expected: FAIL.

- [ ] **Step 3: Implement `hash.rs`**

```rust
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::params::PublicParams;

const DST: &[u8] = b"SIGMA-BBS+-FIAT-SHAMIR-BLS12381";

/// Compute the Fiat-Shamir challenge c.
///
/// Input (720 bytes total):
///   g1 g2 [48+48] | g3 [96] | h0 h1 [48+48] | PK [96]
///   | Com A_prime A_bar D R T1 T2 [7×48]
///
/// # Arguments
/// * `com` — caller-supplied Pedersen commitment (NOT a Proof field)
/// * `a_prime`, `a_bar`, `d`, `cap_r`, `t1`, `t2` — proof commitments
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

    // Static params: 4×G1 (48) + 2×G2 (96) = 384 bytes
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

    // 7×G1 (48) = 336 bytes: Com, A_prime, A_bar, D, R, T1, T2
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

    // RFC 9380 hash_to_field: L=48 for Fr (255-bit field, k=128)
    let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fr>>::new(DST);
    let fields: Vec<Fr> = hasher.hash_to_field(&buf, 1);
    Ok(fields[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
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
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let mut rng = ark_std::rand::rngs::OsRng;
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
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test hash::tests 2>&1`

Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/hash.rs
git commit -m "feat: implement Fiat-Shamir challenge via RFC 9380 hash_to_field"
```

---

## Chunk 3: Prover + Verifier

### Task 8: `prover.rs` — `prove()`

**Files:**
- Modify: `src/prover.rs`

> **Critical implementation notes:**
> - `ProverSecrets` must be dropped (zeroized) at end of function — it is `Drop`, so this is automatic when the binding goes out of scope.
> - Check `m·g1 + r·g2 == com.0` before proceeding.
> - Rejection-sample `r1 ≠ 0` AND `r2 ≠ 0` independently.
> - After computing `A_prime = r1·A`, immediately check `A_prime == G1::zero()`.
> - `z_r3 = Temp_r3 + c·r3` — NO sign flip in response (negation appears explicitly in T2/Eq3).
> - Shared `Temp_m`/`z_m` binds Pedersen `m` to BBS+ `m`.

- [ ] **Step 1: Write the failing test**

```rust
// In src/prover.rs tests (unit-level only; full integration test comes later)
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit};

    fn make_scenario() -> (crate::params::PublicParams, Fr, Fr, crate::bbs::BbsSignature, crate::commitment::PedersenCommitment) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let wrong_com = commit(&params, Fr::rand(&mut ark_std::rand::rngs::OsRng), r);
        let result = prove(&params, &sig, &wrong_com, m, r);
        assert!(matches!(result, Err(crate::errors::SigmaError::ProvingError(_))));
    }

    #[test]
    fn test_prove_zero_a_fails() {
        let (params, m, r, mut sig, com) = make_scenario();
        sig.a = G1Affine::zero();
        let result = prove(&params, &sig, &com, m, r);
        assert!(matches!(result, Err(crate::errors::SigmaError::ProvingError(_))));
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test prover::tests 2>&1 | tail -15`

Expected: FAIL.

- [ ] **Step 3: Implement `prover.rs`**

```rust
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero, Field};

use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::hash::fiat_shamir_challenge;
use crate::params::PublicParams;
use crate::proof::{Proof, ProverSecrets};
use crate::bbs::BbsSignature;

/// Produce a non-interactive Sigma proof.
///
/// Proves: the message `m` inside `com` is correctly BBS+-signed under `params.pk`,
/// without revealing `m`, `sig`, or `r`.
///
/// # Errors
/// - `ProvingError` if `m`/`r` are inconsistent with `com`, or `A_prime` is identity.
/// - `HashError` if the Fiat-Shamir hash fails.
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

    let mut rng = ark_std::rand::rngs::OsRng;

    // §3.3 Signature randomisation
    // Rejection-sample r1 ≠ 0
    let r1 = loop {
        let x = Fr::rand(&mut rng);
        if !x.is_zero() { break x; }
    };
    // Rejection-sample r2 ≠ 0
    let r2 = loop {
        let x = Fr::rand(&mut rng);
        if !x.is_zero() { break x; }
    };

    let r3 = r1.inverse().ok_or_else(|| {
        SigmaError::ProvingError("r1 has no inverse (should never happen)".to_string())
    })?;

    // Compute A_prime = r1·A; check for identity immediately
    let a_prime_proj = sig.a.into_group() * r1;
    let a_prime: G1Affine = a_prime_proj.into_affine();
    if a_prime.is_zero() {
        return Err(SigmaError::ProvingError(
            "A_prime is the identity — invalid or corrupt signature".to_string()
        ));
    }

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

    // §4.1 Commit phase — sample blinding scalars
    let temp_m      = Fr::rand(&mut rng);
    let temp_r      = Fr::rand(&mut rng);
    let temp_e      = Fr::rand(&mut rng);
    let temp_r2     = Fr::rand(&mut rng);
    let temp_r3     = Fr::rand(&mut rng);
    let temp_sprime = Fr::rand(&mut rng);

    // R = Temp_m·g1 + Temp_r·g2
    let cap_r: G1Affine =
        (params.g1.into_group() * temp_m + params.g2.into_group() * temp_r).into_affine();
    // T1 = (-Temp_e)·A_prime + Temp_r2·h0
    let t1: G1Affine =
        (a_prime_proj * (-temp_e) + params.h0.into_group() * temp_r2).into_affine();
    // T2 = (-Temp_r3)·D + Temp_sprime·h0 + Temp_m·h1
    let d_proj = d.into_group();
    let t2: G1Affine =
        (d_proj * (-temp_r3) + params.h0.into_group() * temp_sprime
            + params.h1.into_group() * temp_m)
        .into_affine();

    // §4.2 Fiat-Shamir challenge
    let c = fiat_shamir_challenge(params, com, a_prime, a_bar, d, cap_r, t1, t2)?;

    // §4.3 Response phase — ProverSecrets is dropped (zeroized) at end of scope
    let secrets = ProverSecrets {
        r1, r2, r3, s_prime,
        temp_m, temp_r, temp_e, temp_r2, temp_r3,
        temp_sprime,
    };

    let z_m      = secrets.temp_m      + c * m;
    let z_r      = secrets.temp_r      + c * r;
    let z_e      = secrets.temp_e      + c * sig.e;
    let z_r2     = secrets.temp_r2     + c * secrets.r2;
    let z_r3     = secrets.temp_r3     + c * secrets.r3;      // no sign flip (spec §4.3)
    let z_sprime = secrets.temp_sprime + c * secrets.s_prime;

    // secrets drops here, calling Zeroize::zeroize() via Drop
    drop(secrets);

    Ok(Proof { a_prime, a_bar, d, cap_r, t1, t2, z_m, z_r, z_e, z_r2, z_r3, z_sprime })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit};

    fn make_scenario() -> (PublicParams, Fr, Fr, BbsSignature, PedersenCommitment) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let wrong_com = commit(&params, Fr::rand(&mut ark_std::rand::rngs::OsRng), r);
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
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test prover::tests 2>&1`

Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/prover.rs
git commit -m "feat: implement prove() with signature randomisation and Fiat-Shamir"
```

---

### Task 9: `verifier.rs` — `verify()`

**Files:**
- Modify: `src/verifier.rs`

> **Critical:** Verifier checks run in order:
> 1. `params.pk != G2::zero()` → `InvalidParams`
> 2. `a_prime == 0 || a_bar == 0 || d == 0` → `VerificationFailed(0)`
> 3. Pairing: `e(a_prime, pk) == e(a_bar, g3)` → `VerificationFailed(1)`
> 4. Eq1: `z_m·g1 + z_r·g2 == cap_r + c·Com` → `VerificationFailed(2)`
> 5. Eq2: `(-z_e)·a_prime + z_r2·h0 == t1 + c·(a_bar - d)` → `VerificationFailed(3)`
> 6. Eq3: `(-z_r3)·d + z_sprime·h0 + z_m·h1 == t2 - c·g1` → `VerificationFailed(4)`

- [ ] **Step 1: Write the failing test**

```rust
// In src/verifier.rs tests
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ec::AffineRepr;
    use ark_ff::{UniformRand, Zero};
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit, prover::prove};

    fn make_proof() -> (PublicParams, PedersenCommitment, crate::proof::Proof) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::rand::rngs::OsRng;
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
        // Tamper with a_bar → pairing check fails
        proof.a_bar = ark_bls12_381::G1Affine::generator();
        let result = verify(&params, &com, &proof);
        assert!(matches!(result, Err(SigmaError::VerificationFailed(1))));
    }

    #[test]
    fn test_verify_wrong_com_fails() {
        let (params, _, proof) = make_proof();
        let wrong_com = commit(&params, Fr::rand(&mut ark_std::rand::rngs::OsRng), Fr::rand(&mut ark_std::rand::rngs::OsRng));
        // Eq1 uses Com; different com should fail Eq1
        let result = verify(&params, &wrong_com, &proof);
        assert!(matches!(result, Err(SigmaError::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_flipped_z_m_fails() {
        let (params, com, mut proof) = make_proof();
        proof.z_m = -proof.z_m;
        let result = verify(&params, &com, &proof);
        assert!(matches!(result, Err(SigmaError::VerificationFailed(_))));
    }
}
```

- [ ] **Step 2: Run tests — verify they fail**

Run: `cd /home/argha/sigma && cargo test verifier::tests 2>&1 | tail -15`

Expected: FAIL.

- [ ] **Step 3: Implement `verifier.rs`**

```rust
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;

use crate::commitment::PedersenCommitment;
use crate::errors::SigmaError;
use crate::hash::fiat_shamir_challenge;
use crate::params::PublicParams;
use crate::proof::Proof;

/// Verify a Sigma proof.
///
/// # Errors
/// - `InvalidParams` if `params.pk == G2::zero()`
/// - `VerificationFailed(0)` if any of `a_prime`, `a_bar`, `d` is the identity
/// - `VerificationFailed(1)` if the pairing check fails
/// - `VerificationFailed(2..=4)` if any of Eq1–Eq3 fails
pub fn verify(
    params: &PublicParams,
    com:    &PedersenCommitment,
    proof:  &Proof,
) -> Result<(), SigmaError> {
    use ark_ec::AffineRepr;

    // Guard: valid public key
    if params.pk.is_zero() {
        return Err(SigmaError::InvalidParams);
    }

    // Soundness pre-checks (all checked before proceeding)
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
        let rhs: G1Affine =
            (proof.t1.into_group() + a_bar_minus_d * c).into_affine();
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
    use ark_ff::{UniformRand, Zero};
    use crate::{params::setup, bbs::{keygen, sign}, commitment::commit, prover::prove};

    fn make_proof() -> (PublicParams, PedersenCommitment, Proof) {
        let g3 = ark_bls12_381::G2Affine::generator();
        let kp = keygen(&g3).unwrap();
        let params = setup(kp.pk).unwrap();
        let mut rng = ark_std::rand::rngs::OsRng;
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
        let wrong_com = commit(&params, Fr::rand(&mut ark_std::rand::rngs::OsRng), Fr::rand(&mut ark_std::rand::rngs::OsRng));
        let result = verify(&params, &wrong_com, &proof);
        assert!(matches!(result, Err(SigmaError::VerificationFailed(_))));
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
```

- [ ] **Step 4: Run tests — verify they pass**

Run: `cd /home/argha/sigma && cargo test verifier::tests 2>&1`

Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/argha/sigma && git add src/verifier.rs
git commit -m "feat: implement verify() with pairing check and three G1 equation checks"
```

---

## Chunk 4: Integration Tests + Final Wiring

### Task 10: Fix `lib.rs` and integration tests

**Files:**
- Modify: `src/lib.rs` (finalise re-exports)
- Create: `tests/integration.rs`

- [ ] **Step 1: Write `tests/integration.rs`** (lib.rs is NOT yet finalised — this triggers the TDD red state)

```rust
// tests/integration.rs
use sigma::*;
use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_ec::AffineRepr;

fn setup_scenario() -> (PublicParams, Fr, Fr, BbsSignature, PedersenCommitment) {
    let g3 = ark_bls12_381::G2Affine::generator();
    let kp = keygen(&g3).expect("keygen failed");
    let params = setup(kp.pk).expect("setup failed");
    let mut rng = ark_std::rand::rngs::OsRng;
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
    // Non-deterministic randomisation: two proofs from same inputs must both verify
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
    // A different m produces a different Com; Eq1 checks z_m·g1 + z_r·g2 == cap_r + c·Com
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
```

- [ ] **Step 2: Run — verify compile error (red state)**

Run: `cd /home/argha/sigma && cargo test --test integration 2>&1 | tail -20`

Expected: compile error such as `error[E0412]: cannot find type 'BbsSignature'` — this is the required TDD red signal.

- [ ] **Step 3: Finalise `src/lib.rs` with correct re-exports**

```rust
pub mod errors;
pub mod params;
pub mod bbs;
pub mod commitment;
pub mod proof;
pub mod hash;
pub mod prover;
pub mod verifier;

pub use crate::errors::SigmaError;
pub use crate::params::{PublicParams, setup};
pub use crate::bbs::{SecretKey, KeyPair, BbsSignature, keygen, sign};
pub use crate::commitment::{PedersenCommitment, commit};
pub use crate::proof::Proof;
pub use crate::prover::prove;
pub use crate::verifier::verify;
// ProverSecrets is intentionally NOT re-exported
```

- [ ] **Step 4: Run integration tests — verify they pass (green state)**

Run: `cd /home/argha/sigma && cargo test --test integration 2>&1 | tail -20`

Expected: all integration tests PASS.

- [ ] **Step 5: Run all tests**

Run: `cd /home/argha/sigma && cargo test 2>&1`

Expected: All tests PASS (unit tests across all modules + all integration tests).

- [ ] **Step 6: Run `cargo clippy` and fix any warnings**

Run: `cd /home/argha/sigma && cargo clippy -- -D warnings 2>&1`

Expected: no errors. Fix any `clippy` warnings before committing.

- [ ] **Step 7: Verify release build**

Run: `cd /home/argha/sigma && cargo check --release 2>&1`

Expected: compiles clean.

- [ ] **Step 8: Commit**

```bash
cd /home/argha/sigma && git add src/lib.rs tests/
git commit -m "feat: complete integration test suite — full prove/verify pipeline verified"
```

---

## Completion Checklist

- [ ] `cargo test` — all tests pass (unit + integration)
- [ ] `cargo clippy -- -D warnings` — no warnings
- [ ] `cargo check --release` — compiles clean in release mode
- [ ] All spec §13 test scenarios covered: 6 flip-z_* tests + wrong-Com + tampered-a_bar + zero-A (10 test functions total across unit + integration)
- [ ] `ProverSecrets` not re-exported from `lib.rs`
- [ ] `B` not stored in `BbsSignature` (only `A`, `e`, `s`)
- [ ] Fiat-Shamir input is exactly 720 bytes
- [ ] `r1 ≠ 0` and `r2 ≠ 0` enforced via rejection sampling
- [ ] `A_prime == 0` guard fires before computing `A_bar`/`D`
