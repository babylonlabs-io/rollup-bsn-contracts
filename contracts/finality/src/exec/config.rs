use cosmwasm_std::{DepsMut, MessageInfo, Response};

use crate::error::ContractError;
use crate::msg::{
    validate_finality_signature_interval, validate_max_msgs_per_interval, validate_min_pub_rand,
    validate_rate_limiting_interval, BabylonMsg,
};
use crate::state::config::{get_config, set_config, ADMIN};
use babylon_bindings::BabylonQuery;

/// Handle updating the contract configuration
pub fn handle_update_config(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    min_pub_rand: Option<u64>,
    max_msgs_per_interval: Option<u32>,
    rate_limiting_interval: Option<u64>,
    bsn_activation_height: Option<u64>,
    finality_signature_interval: Option<u64>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Only admin can update config
    ADMIN.assert_admin(deps.as_ref(), &info.sender)?;

    // Get current config
    let mut config = get_config(deps.storage)?;
    let mut updated_fields = Vec::new();

    // Update min_pub_rand if provided
    if let Some(new_min_pub_rand) = min_pub_rand {
        validate_min_pub_rand(new_min_pub_rand)?;
        config.min_pub_rand = new_min_pub_rand;
        updated_fields.push("min_pub_rand");
    }

    // Update rate limiting config if any rate limiting fields are provided
    if let Some(new_max_msgs) = max_msgs_per_interval {
        validate_max_msgs_per_interval(new_max_msgs)?;
        config.rate_limiting.max_msgs_per_interval = new_max_msgs;
        updated_fields.push("max_msgs_per_interval");
    }

    if let Some(new_interval) = rate_limiting_interval {
        validate_rate_limiting_interval(new_interval)?;
        config.rate_limiting.block_interval = new_interval;
        updated_fields.push("rate_limiting_interval");
    }

    // Update bsn_activation_height if provided (no validation needed - any u64 is valid)
    if let Some(new_activation_height) = bsn_activation_height {
        config.bsn_activation_height = new_activation_height;
        updated_fields.push("bsn_activation_height");
    }

    // Update finality_signature_interval if provided
    if let Some(new_finality_interval) = finality_signature_interval {
        validate_finality_signature_interval(new_finality_interval)?;
        config.finality_signature_interval = new_finality_interval;
        updated_fields.push("finality_signature_interval");
    }

    // Check if any fields were actually updated
    if updated_fields.is_empty() {
        return Err(ContractError::NoConfigFieldsToUpdate);
    }

    // Save the updated config
    set_config(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "update_config")
        .add_attribute("updated_fields", updated_fields.join(","))
        .add_attribute("num_updated", updated_fields.len().to_string()))
} 