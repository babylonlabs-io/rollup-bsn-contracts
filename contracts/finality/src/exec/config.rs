use cosmwasm_std::{DepsMut, MessageInfo, Response};

use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::{get_config, set_config, ADMIN};
use crate::validation::{
    validate_max_msgs_per_interval, validate_min_pub_rand, validate_rate_limiting_interval,
};
use babylon_bindings::BabylonQuery;

/// Handle updating the contract configuration
pub fn handle_update_config(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    min_pub_rand: Option<u64>,
    max_msgs_per_interval: Option<u32>,
    rate_limiting_interval: Option<u64>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Only admin can update config
    ADMIN.assert_admin(deps.as_ref(), &info.sender)?;

    // Get current config
    let mut config = get_config(deps.storage)?;
    let mut has_updates = false;

    // Update min_pub_rand if provided
    if let Some(new_min_pub_rand) = min_pub_rand {
        validate_min_pub_rand(new_min_pub_rand)?;
        config.min_pub_rand = new_min_pub_rand;
        has_updates = true;
    }

    // Update rate limiting config if any rate limiting fields are provided
    if let Some(new_max_msgs) = max_msgs_per_interval {
        validate_max_msgs_per_interval(new_max_msgs)?;
        config.rate_limiting.max_msgs_per_interval = new_max_msgs;
        has_updates = true;
    }

    if let Some(new_interval) = rate_limiting_interval {
        validate_rate_limiting_interval(new_interval)?;
        config.rate_limiting.block_interval = new_interval;
        has_updates = true;
    }

    // Check if any fields were actually updated
    if !has_updates {
        return Err(ContractError::NoConfigFieldsToUpdate);
    }

    // Save the updated config
    set_config(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}
