pub mod errors;
pub mod params;
pub mod bbs;
pub mod commitment;
pub mod proof;
pub(crate) mod hash;
pub(crate) mod prover;
pub(crate) mod verifier;

pub use crate::errors::SigmaError;
pub use crate::params::{PublicParams, setup};
pub use crate::bbs::{SecretKey, KeyPair, BbsSignature, keygen, sign};
pub use crate::commitment::{PedersenCommitment, commit};
pub use crate::proof::Proof;
pub use crate::prover::prove;
pub use crate::verifier::verify;
// ProverSecrets is intentionally NOT re-exported
