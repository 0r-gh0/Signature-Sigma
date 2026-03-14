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
