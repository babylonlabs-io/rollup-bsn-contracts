use crate::error::ContractError;

pub const MAX_BSN_ID_LENGTH: usize = 100;

/// Validate BSN ID format
pub fn validate_bsn_id(bsn_id: &str) -> Result<(), ContractError> {
    if bsn_id.is_empty() {
        return Err(ContractError::InvalidBsnId(
            "BSN ID cannot be empty".to_string(),
        ));
    }

    // Check for valid characters (alphanumeric, hyphens, underscores)
    if !bsn_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ContractError::InvalidBsnId(
            "BSN ID can only contain alphanumeric characters, hyphens, and underscores"
                .to_string(),
        ));
    }

    // Check length (reasonable bounds)
    if bsn_id.len() > MAX_BSN_ID_LENGTH {
        return Err(ContractError::InvalidBsnId(
            format!("BSN ID cannot exceed {} characters", MAX_BSN_ID_LENGTH),
        ));
    }

    Ok(())
}

/// Validate minimum public randomness value
pub fn validate_min_pub_rand(min_pub_rand: u64) -> Result<(), ContractError> {
    if min_pub_rand == 0 {
        return Err(ContractError::InvalidMinPubRand(min_pub_rand));
    }
    Ok(())
}

/// Validate rate limiting interval
pub fn validate_rate_limiting_interval(interval: u64) -> Result<(), ContractError> {
    if interval == 0 {
        return Err(ContractError::InvalidRateLimitingInterval(interval));
    }
    Ok(())
}

/// Validate maximum messages per interval
pub fn validate_max_msgs_per_interval(max_msgs: u32) -> Result<(), ContractError> {
    if max_msgs == 0 {
        return Err(ContractError::InvalidMaxMsgsPerInterval(max_msgs));
    }
    Ok(())
}

/// Validate finality signature interval
pub fn validate_finality_signature_interval(interval: u64) -> Result<(), ContractError> {
    if interval == 0 {
        return Err(ContractError::InvalidFinalitySignatureInterval(interval));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bsn_id_empty() {
        let result = validate_bsn_id("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_validate_bsn_id_invalid_characters() {
        let invalid_ids = vec!["invalid@id", "test#id", "chain$1"];
        for id in invalid_ids {
            let result = validate_bsn_id(id);
            assert!(result.is_err(), "Should fail for invalid ID: {}", id);
            assert!(matches!(result.unwrap_err(), ContractError::InvalidBsnId(_)));
        }
    }

    #[test]
    fn test_validate_bsn_id_valid() {
        let valid_ids = vec![
            "op-stack-l2-11155420",
            "valid-bsn_123",
            "test_chain",
            "chain-1",
            "abc123",
        ];
        for id in valid_ids {
            let result = validate_bsn_id(id);
            assert!(result.is_ok(), "Should succeed for valid ID: {}", id);
        }
    }

    #[test]
    fn test_validate_bsn_id_length() {
        // Test maximum length
        let long_id = "a".repeat(MAX_BSN_ID_LENGTH);
        assert!(validate_bsn_id(&long_id).is_ok());

        // Test exceeding maximum length
        let too_long_id = "a".repeat(MAX_BSN_ID_LENGTH + 1);
        assert!(validate_bsn_id(&too_long_id).is_err());
    }

    #[test]
    fn test_validate_min_pub_rand() {
        assert!(validate_min_pub_rand(0).is_err());
        assert!(validate_min_pub_rand(1).is_ok());
        assert!(validate_min_pub_rand(100).is_ok());
    }

    #[test]
    fn test_validate_rate_limiting_interval() {
        assert!(validate_rate_limiting_interval(0).is_err());
        assert!(validate_rate_limiting_interval(1).is_ok());
        assert!(validate_rate_limiting_interval(1000).is_ok());
    }

    #[test]
    fn test_validate_max_msgs_per_interval() {
        assert!(validate_max_msgs_per_interval(0).is_err());
        assert!(validate_max_msgs_per_interval(1).is_ok());
        assert!(validate_max_msgs_per_interval(100).is_ok());
    }

    #[test]
    fn test_validate_finality_signature_interval() {
        assert!(validate_finality_signature_interval(0).is_err());
        assert!(validate_finality_signature_interval(1).is_ok());
        assert!(validate_finality_signature_interval(100).is_ok());
    }
} 