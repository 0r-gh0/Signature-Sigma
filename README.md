# Sigma Protocol over BBS+ Signatures — Design Spec
**Date:** 2026-03-14  **Rev:** 9

---

## 1. Goal

Implement a zero-knowledge Sigma Protocol in Rust that allows a Prover to convince a Verifier that the message `m` inside a Pedersen commitment is correctly signed under a BBS+ signature, without revealing `m`, the signature, or the signing randomness. Non-interactive via Fiat-Shamir.

---

## 2. Cryptographic Setting

**Curve:** BLS12-381

| Symbol | Type | Description |
|---|---|---|
| `g1, g2` | G1 | Public generators for Pedersen commitment; `g1` also serves as the constant base point in BBS+ `B = s·h0 + m·h1 + g1` |
| `g3` | G2 | G2 generator for BBS+ public key (used in pairings as second argument) |
| `h0, h1` | G1 | BBS+ message generators |
| `x` | Fr | BBS+ secret key |
| `PK = x·g3` | G2 | BBS+ public key |
| `m` | Fr | Secret message |
| `r` | Fr | Pedersen blinding scalar |
| `e, s` | Fr | BBS+ signature randomness |
| `A, B` | G1 | BBS+ signature components |

### 2.1 Security Assumptions

- All generators `g1, g2, h0, h1 ∈ G1` and `g3 ∈ G2` are **independent**: no party knows any discrete-log relation between them (e.g., no known `α` such that `g2 = α·g1`). This is required for the binding property of the cross-commitment proof.
- Generators SHOULD be produced via `hash_to_curve` (RFC 9380) from distinct domain-separated seeds to ensure independence.

---

## 3. Sub-Protocols

### 3.1 Pedersen Commitment

```
Com = m·g1 + r·g2   (public output, in G1)
```

### 3.2 BBS+ Signing

```
B = s·h0 + m·h1 + g1        (B ∈ G1)
A = B / (x + e)              i.e. (x+e)·A = B    (A ∈ G1)
Sigma = (A, e, s)
```

**Guards in `sign()`:**
- If `sk.0 == Fr::zero()`, return `SigmaError::SigningError("secret key is zero")` immediately.
- If `x + e == Fr::zero()`, resample `e` and retry.
- After computing `B`, assert `B != G1::zero()` via `debug_assert!` (sanity; astronomically unlikely with valid params).

Pairing check (for reference — the Sigma Protocol replaces this check for the verifier):
```
e(A, PK + e·g3) == e(B, g3)    (A, B ∈ G1;  PK + e·g3, g3 ∈ G2)  ✓
```

### 3.3 Signature Randomisation

At proof time the prover first reconstructs `B` from the stored signature:
```
B = s·h0 + m·h1 + g1        (recomputed from Sigma.s, m, and PublicParams)
```

Then samples `r1, r2 ← Fr` with rejection-sampling until both are non-zero and computes:
```
r3      = r1⁻¹              (field inverse; well-defined since r1 ≠ 0)
A_prime = r1·A              (A_prime ∈ G1)
A_bar   = r1·B - e·A_prime  (A_bar ∈ G1;  equivalently A_bar = x·A_prime)
D       = r1·B - r2·h0      (D ∈ G1)
s_prime = s - r2·r3         (s_prime ∈ Fr)
```

**Guard for `r2 = 0`:** if `r2 == Fr::zero()`, resample. Reason: `r2 = 0` collapses `D = r1·B`
and `s_prime = s`, leaking the raw BBS+ blinding scalar `s` (zero-knowledge failure).

After this step the prover must persist `(r1, r2, r3, s_prime)` in a `ProverSecrets`
struct (see §7) along with the blinding scalars from §4.1.

---

## 4. Full Non-Interactive Sigma Protocol

### 4.1 Prover: Commit Phase

Sample blinding scalars:
```
Temp_m, Temp_r, Temp_e, Temp_r2, Temp_r3, Temp_sprime  ← Fr (uniform random)
```

Compute randomised commitments:
```
R  = Temp_m·g1 + Temp_r·g2              (R ∈ G1, Pedersen blinding commitment)
T1 = (-Temp_e)·A_prime + Temp_r2·h0    (T1 ∈ G1)
T2 = (-Temp_r3)·D + Temp_sprime·h0 + Temp_m·h1  (T2 ∈ G1)
```

All six `Temp_*` scalars are stored in `ProverSecrets`.

### 4.2 Fiat-Shamir Challenge

Hash all public parameters and all randomised commitments.
`Com` is the Pedersen commitment supplied by the caller — it is **not** a field in `Proof`.

```
c = hash_to_field(
      g1 || g2 || g3 || h0 || h1 || PK ||
      Com || A_prime || A_bar || D || R || T1 || T2
    )
```

See §8 for the exact byte layout (720 bytes total). DST = `b"SIGMA-BBS+-FIAT-SHAMIR-BLS12381"`.

> **Note: B is intentionally absent from the hash.** The standard Fiat-Shamir soundness argument works by extraction via rewinding: given two accepting transcripts `(A_prime, A_bar, D, R, T1, T2, c, z_*)` and `(A_prime, A_bar, D, R, T1, T2, c', z'_*)` with `c ≠ c'` but identical commitments, we can extract witnesses `(e, r2, r3, s', m)` satisfying the relation equations. From the extracted `(r3, s', m)` the extractor recovers `B = s·h0 + m·h1 + g1` directly (algebraically, from `r3·D + m·h1 + s'·h0 + g1 = 0` mod the group). B is therefore bound to the transcript through the committed group elements `D, A_prime, A_bar` (all in the hash) and the extracted witnesses — without B itself needing to be in the hash. This matches the IETF BBS Signatures draft design.

### 4.3 Prover: Response Phase

Using `s_prime` from §3.3 (stored in `ProverSecrets`) and all `Temp_*` from §4.1:
```
z_m      = Temp_m      + c·m
z_r      = Temp_r      + c·r
z_e      = Temp_e      + c·e
z_r2     = Temp_r2     + c·r2
z_r3     = Temp_r3     + c·r3
z_sprime = Temp_sprime + c·s_prime     (s_prime from §3.3)
```

**Intentional shared blinding:** `Temp_m` and `z_m` appear in both Eq1 (Pedersen) and Eq3
(BBS+ message term). This is deliberate — using the same `z_m` in both equations is what
cryptographically binds the `m` in the Pedersen commitment to the `m` in the BBS+ signature.
Using two independent blinding scalars here would break this cross-commitment binding.

**Sign convention for `z_r3`:** `z_r3 = Temp_r3 + c·r3` is computed **without** a sign flip.
The negation `(-z_r3)` appears explicitly in the T2 formula (§4.1) and in Eq3 (§4.5). Do not
absorb the negative sign into the response formula.

### 4.4 Proof Output

```
Proof {
    // BBS+ randomised public values
    a_prime:  G1Affine,   // A_prime = r1·A
    a_bar:    G1Affine,   // A_bar   = r1·B - e·A_prime  (= x·A_prime)
    d:        G1Affine,   // D       = r1·B - r2·h0
    // Pedersen blinding commitment (R — the G1 point, not the scalar r)
    cap_r:    G1Affine,
    // Sigma commitments
    t1:       G1Affine,
    t2:       G1Affine,
    // Responses
    z_m:      Fr,
    z_r:      Fr,
    z_e:      Fr,
    z_r2:     Fr,
    z_r3:     Fr,
    z_sprime: Fr,
}
```

### 4.5 Verifier Checks

The verifier recomputes `c` via the same Fiat-Shamir hash. The `Com` input to the hash is
`com.0` — the caller-supplied Pedersen commitment argument to `verify()`, not a field in `Proof`.

**Soundness pre-checks:** Reject with `SigmaError::VerificationFailed(0)` if any of the following hold (check all three before proceeding):
- `proof.a_prime == G1::zero()` — trivially satisfies the pairing check `e(O,PK) = 1_GT`, enabling forgery
- `proof.a_bar == G1::zero()` — reachable with `x = 0` (degenerate key) or via a malicious proof; collapses pairing check
- `proof.d == G1::zero()` — makes `(-z_r3)·d = O`, removing `z_r3` from Eq3 entirely

Also check `params.pk != G2::zero()`; if so return `SigmaError::InvalidParams` before doing anything else.

**Pairing check (mandatory — BBS+ binding):**
```
e(proof.a_prime, params.pk) == e(proof.a_bar, params.g3)
```
This checks that `A_bar = x·A_prime`, binding the proof to the specific BBS+ public key.
Without this check the three G1 equations below are not a proof of knowledge of a valid BBS+
signature — a prover could fabricate `A_prime`, `A_bar`, `D` freely.

**Three G1 equations (all in G1):**
```
Eq1: z_m·g1 + z_r·g2                        == cap_r + c·Com
Eq2: (-z_e)·a_prime + z_r2·h0               == t1 + c·(a_bar - d)
Eq3: (-z_r3)·d + z_sprime·h0 + z_m·h1       == t2 - c·g1
```

Return `SigmaError::VerificationFailed(n)` on the first failing check, using these codes:
- `0` — identity pre-check (`a_prime == G1::zero()`)
- `1` — pairing check
- `2` — Eq1 fails
- `3` — Eq2 fails
- `4` — Eq3 fails

---

## 5. Algebraic Correctness

**Eq1:**
```
z_m·g1 + z_r·g2
= (Temp_m + c·m)·g1 + (Temp_r + c·r)·g2
= (Temp_m·g1 + Temp_r·g2) + c·(m·g1 + r·g2)
= cap_r + c·Com  ✓
```

**Eq2:** First, `a_bar - d = (r1·B - e·A_prime) - (r1·B - r2·h0) = -e·A_prime + r2·h0`. Then:
```
(-z_e)·a_prime + z_r2·h0
= -(Temp_e + c·e)·a_prime + (Temp_r2 + c·r2)·h0
= T1 + c·(-e·a_prime + r2·h0)
= T1 + c·(a_bar - d)  ✓
```

**Eq3:** Full expansion of the secret-witness combination:
```
-r3·D + s_prime·h0 + m·h1
= -(1/r1)·(r1·B - r2·h0) + (s - r2/r1)·h0 + m·h1
= -B + (r2/r1)·h0 + s·h0 - (r2/r1)·h0 + m·h1
= -B + s·h0 + m·h1
= -(s·h0 + m·h1 + g1) + s·h0 + m·h1    [using B = s·h0 + m·h1 + g1]
= -g1
```
Therefore:
```
(-z_r3)·d + z_sprime·h0 + z_m·h1
= T2 + c·(-r3·d + s_prime·h0 + m·h1)
= T2 + c·(-g1)
= T2 - c·g1  ✓
```

**Pairing check:** `e(A_prime, PK) = e(r1·A, x·g3) = e(A, g3)^(r1·x)`.
`e(A_bar, g3) = e(r1·B - e·A_prime, g3) = e(r1·(x+e)·A - e·r1·A, g3) = e(r1·x·A, g3) = e(A, g3)^(r1·x)`. ✓

---

## 6. Module Architecture

```
sigma/
├── Cargo.toml
└── src/
    ├── lib.rs          # pub use of public API
    ├── errors.rs       # SigmaError (thiserror)
    ├── params.rs       # PublicParams { g1, g2, g3, h0, h1, pk }
    ├── bbs.rs          # SecretKey, KeyPair, BbsSignature, sign()
    ├── commitment.rs   # PedersenCommitment, commit()
    ├── proof.rs        # Proof struct + ProverSecrets (internal)
    ├── prover.rs       # prove(&params, &sig, &com, m, r) -> Result<Proof, SigmaError>
    ├── verifier.rs     # verify(&params, &com, &proof) -> Result<(), SigmaError>
    └── hash.rs         # fiat_shamir_challenge() — RFC 9380 hash_to_field
```

| Module | Exports | Dependencies |
|---|---|---|
| `errors` | `SigmaError` | none |
| `params` | `PublicParams`, `setup()` | ark-bls12-381, errors |
| `bbs` | `SecretKey`, `KeyPair`, `BbsSignature`, `sign()`, `keygen()` | params, errors |
| `commitment` | `PedersenCommitment`, `commit()` | params |
| `proof` | `Proof`, `ProverSecrets` (internal) | params |
| `hash` | `fiat_shamir_challenge()` | params, proof, errors |
| `prover` | `prove()` | all above |
| `verifier` | `verify()` | params, commitment, proof, hash, errors |

---

## 7. Key Type Definitions

```rust
// params.rs
pub struct PublicParams {
    pub g1:  G1Affine,   // G1 generator (Pedersen base + BBS+ B base)
    pub g2:  G1Affine,   // G1 generator (Pedersen binding)
    pub g3:  G2Affine,   // G2 generator (BBS+ PK base)
    pub h0:  G1Affine,   // BBS+ message generator
    pub h1:  G1Affine,   // BBS+ message generator
    pub pk:  G2Affine,   // BBS+ public key = x·g3
}

// bbs.rs
pub struct SecretKey(pub Fr);
pub struct KeyPair { pub sk: SecretKey, pub pk: G2Affine }
// B is NOT stored; the prover reconstructs it as s·h0 + m·h1 + g1
pub struct BbsSignature { pub a: G1Affine, pub e: Fr, pub s: Fr }

// commitment.rs
pub struct PedersenCommitment(pub G1Affine);

// proof.rs  (Proof is public; ProverSecrets is internal)
pub struct Proof {
    pub a_prime:  G1Affine,   // r1·A
    pub a_bar:    G1Affine,   // r1·B - e·A_prime  (= x·A_prime)
    pub d:        G1Affine,   // r1·B - r2·h0
    pub cap_r:    G1Affine,   // Pedersen blinding commitment R (NOT the scalar r)
    pub t1:       G1Affine,
    pub t2:       G1Affine,
    pub z_m:      Fr,
    pub z_r:      Fr,
    pub z_e:      Fr,
    pub z_r2:     Fr,
    pub z_r3:     Fr,
    pub z_sprime: Fr,
}

// Internal to proof.rs — not exported from lib.rs
pub(crate) struct ProverSecrets {
    pub r1:           Fr,
    pub r2:           Fr,
    pub r3:           Fr,       // = r1⁻¹
    pub s_prime:      Fr,       // = s - r2·r3
    pub temp_m:       Fr,
    pub temp_r:       Fr,
    pub temp_e:       Fr,
    pub temp_r2:      Fr,
    pub temp_r3:      Fr,
    pub temp_sprime:  Fr,
}
```

---

## 8. Fiat-Shamir Hash (RFC 9380)

### Input byte layout (total = 720 bytes)

All points use arkworks' canonical **compressed** serialisation (`CanonicalSerialize` from
`ark-serialize`) with the ZCash flag-byte convention:
- G1 compressed: 48 bytes (with the compression/infinity flags in the high bits of byte 0)
- G2 compressed: 96 bytes (same convention, over Fp2)

| Field | Group | Bytes | Running offset |
|---|---|---|---|
| `g1`      | G1 | 48  | 0   |
| `g2`      | G1 | 48  | 48  |
| `g3`      | G2 | 96  | 96  |
| `h0`      | G1 | 48  | 192 |
| `h1`      | G1 | 48  | 240 |
| `PK`      | G2 | 96  | 288 |
| `Com`     | G1 | 48  | 384 |
| `A_prime` | G1 | 48  | 432 |
| `A_bar`   | G1 | 48  | 480 |
| `D`       | G1 | 48  | 528 |
| `R`       | G1 | 48  | 576 |
| `T1`      | G1 | 48  | 624 |
| `T2`      | G1 | 48  | 672 |

**Total:** 6 static params (4×G1 + 2×G2) = 4×48 + 2×96 = 384 bytes.
6 proof-bound G1 points (`A_prime, A_bar, D, R, T1, T2`) + 1 caller-supplied G1 point (`Com`) = 7×48 = 336 bytes.
(`Com` is taken from the `com` argument to `prove()`/`verify()`, not from the `Proof` struct.)
Grand total = **720 bytes**.

### hash_to_field call

`Fr` for BLS12-381 has a 255-bit scalar field modulus (`r`, the group order — not to be confused with `p`, the 381-bit base field characteristic). Per RFC 9380 §5:
`L = ceil((ceil(log2(r_scalar)) + k) / 8) = ceil((255 + 128) / 8) = 48` bytes (128-bit security, `k=128`).
Note: this is distinct from `Fp` (base field, 381-bit → `L = ceil((381+128)/8) = 64`); use **48** here, not 64.

```rust
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use sha2::Sha256;

// DST: 31 bytes, valid per RFC 9380 §3.1 (requires ≥ 1 byte, recommends ≥ 16)
const DST: &[u8] = b"SIGMA-BBS+-FIAT-SHAMIR-BLS12381";

// DefaultFieldHasher<Sha256, 128> uses expand_message_xmd internally (RFC 9380 §5.4.1)
// The 128 constant is the security parameter in bits
let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fr>>::new(DST);
let fields: Vec<Fr> = hasher.hash_to_field(&msg_bytes, 1);
let c: Fr = fields[0];
```

Output: a single `Fr` element used as challenge `c`.

---

## 9. Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum SigmaError {
    #[error("BBS+ signing failed: {0}")]
    SigningError(String),

    #[error("Invalid public parameters")]
    InvalidParams,

    #[error("Proving failed: {0}")]
    ProvingError(String),   // r1 = 0 (after retries), A_prime = 0

    #[error("Proof verification failed: check {0} did not hold")]
    // 0=identity pre-check, 1=pairing, 2=Eq1, 3=Eq2, 4=Eq3
    VerificationFailed(u8),

    #[error("Hash to field error: {0}")]
    HashError(String),
}
```

### Prover-side guards (in `prove()`)

Perform these checks **in order** at the start of the randomisation step, before computing `A_bar`, `D`, etc.:

1. Compute `A_prime = r1·A` immediately after sampling `r1`.
2. **Check `A_prime == G1::zero()` before any further computation.** If so, return `SigmaError::ProvingError("A_prime is the identity — invalid or corrupt signature")`. Do not compute `A_bar` or `D` using a zero `A_prime`.

- Sample `r1` until `r1 != Fr::zero()` (rejection sampling). Reasons: (1) `r3 = r1⁻¹` requires `r1 ≠ 0`; arkworks silently returns zero for inversion of zero, corrupting `r3` and all derived values. (2) `r1 = 0` produces `A_prime = O`, enabling forgery.
- Sample `r2` until `r2 != Fr::zero()` (rejection sampling). Reasons: (1) `r2 = 0` collapses `s_prime = s`, leaking `s`. (2) `r2 = 0` sets `D = r1·B = a_bar + e·a_prime`, exposing the `D`/`A_bar` linear relation.
- `prove()` does **not** re-validate the BBS+ signature. `BbsSignature` is assumed to come from `sign()`. A corrupt signature produces a `Proof` that fails `verify()`. Trust assumption: `BbsSignature` is always the output of `sign()`, never from untrusted deserialization (§14 excludes deserialization support).
- Inside `prove()`, check `m·g1 + r·g2 == com.0` before proceeding. If not, return `SigmaError::ProvingError("m/r inconsistent with commitment")`.
- `ProverSecrets` MUST be dropped (zeroed via `zeroize`) immediately after the response phase completes inside `prove()`. Never returned to the caller.

### Verifier-side guards (in `verify()`)

- Check `params.pk != G2::zero()` → `SigmaError::InvalidParams`.
- If any of `proof.a_prime`, `proof.a_bar`, or `proof.d` is `G1::zero()` → `SigmaError::VerificationFailed(0)` (pre-check covers all three identity failures under code 0).
- Pairing check: if `e(a_prime, pk) != e(a_bar, g3)`, return `SigmaError::VerificationFailed(1)`.

---

## 10. Public API (lib.rs re-exports)

```rust
pub use crate::errors::SigmaError;
pub use crate::params::{PublicParams, setup};
pub use crate::bbs::{SecretKey, KeyPair, BbsSignature, keygen, sign};
pub use crate::commitment::{PedersenCommitment, commit};
pub use crate::proof::Proof;
pub use crate::prover::prove;
pub use crate::verifier::verify;
```

`ProverSecrets` is **not** re-exported (internal to the proving computation).

---

## 11. Function Signatures

```rust
// params.rs
// Construct PublicParams by hashing to curve for G1 generators and using the
// standard BLS12-381 G2 generator for g3. Caller provides pk = x·g3.
//
// G1 generator DSTs (used with hash_to_curve per RFC 9380, msg = b""):
//   g1: b"SIGMA-BBS-G1-BASE-BLS12381"
//   g2: b"SIGMA-BBS-G1-BIND-BLS12381"
//   h0: b"SIGMA-BBS-H0-BLS12381"
//   h1: b"SIGMA-BBS-H1-BLS12381"
// The message input to hash_to_curve is b"" (empty) for all four generators.
// Callers must not change the message; changing it produces incompatible generators.
// g3: ark_bls12_381::G2Affine::generator() (the standard BLS12-381 G2 generator)
// Returns InvalidParams if pk == G2::zero()
pub fn setup(pk: G2Affine) -> Result<PublicParams, SigmaError>;

// bbs.rs
// Sample x ← Fr \ {0} (rejection-sampling loop), compute pk = x·g3.
// Returns Result for consistency with the rest of the API; in practice never fails
// (probability of needing a resample is ≈ 2^{-255} per attempt).
pub fn keygen(g3: &G2Affine) -> Result<KeyPair, SigmaError>;

// bbs.rs
// Guard: sk.0 != Fr::zero() → SigningError("secret key is zero")
// Guard: resamples e if x + e == Fr::zero()
// Internal sanity check: uses debug_assert! to verify (sk.0 + e)·A == B.
// Panics in debug builds if the implementation has an arithmetic bug.
// In release builds the assertion is elided; sign() is infallible beyond the x+e=0 guard.
pub fn sign(
    params: &PublicParams,
    sk:     &SecretKey,
    m:      Fr,
) -> Result<BbsSignature, SigmaError>;

// commitment.rs  (infallible — no field operations can fail)
pub fn commit(params: &PublicParams, m: Fr, r: Fr) -> PedersenCommitment;

// prover.rs
// NOTE: does NOT take SecretKey — only the already-computed signature
pub fn prove(
    params:  &PublicParams,
    sig:     &BbsSignature,
    com:     &PedersenCommitment,
    m:       Fr,
    r:       Fr,
) -> Result<Proof, SigmaError>;

// verifier.rs
pub fn verify(
    params:  &PublicParams,
    com:     &PedersenCommitment,
    proof:   &Proof,
) -> Result<(), SigmaError>;
```

---

## 12. Dependencies

```toml
[dependencies]
ark-bls12-381 = "0.4"
ark-ec        = "0.4"
ark-ff        = "0.4"
ark-std       = "0.4"
ark-serialize = "0.4"   # CanonicalSerialize for point serialisation in hash.rs
thiserror     = "1"
sha2          = "0.10"
zeroize       = { version = "1", features = ["derive"] }   # zeroise ProverSecrets after use
# NOTE: hash_to_field comes from ark-ff (already listed above).
# Exact import: ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField}
# No additional crate required for hash_to_field.
```

---

## 13. Testing Strategy

- Unit: `sign()` → verify pairing `e(A, PK+e·g3) == e(B, g3)`
- Unit: `commit()` → recover Com from known `m, r`
- Integration (happy path): `sign()` → `commit()` → `prove()` → `verify()` succeeds
- Negative: flip any `z_*` scalar → `VerificationFailed`
- Negative: wrong `Com` (different `m`) → Eq1 fails (`VerificationFailed(2)`)
- Negative: tamper with `a_bar` → pairing check fails (`VerificationFailed(1)`)
- Negative: `A = G1::zero()` as signature input to `prove()` → `ProvingError`

---

## 14. Non-Goals

- No serialisation/deserialisation of `Proof`
- No multi-message BBS+ (single message `m` only)
- No hiding of `A_prime`/`A_bar`/`D` from the verifier
