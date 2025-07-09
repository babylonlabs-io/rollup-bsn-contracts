use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::{get_config, ADMIN, CONFIG};
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{DepsMut, MessageInfo, Response};

// Enable or disable the finality gadget.
// Only callable by contract admin.
// If disabled, the verifier should bypass the EOTS verification logic, allowing the OP derivation
// derivation pipeline to pass through. Note this should be implemented in the verifier and is not
// enforced by the contract itself.
pub fn set_enabled(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    enabled: bool,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Check caller is admin
    check_admin(&deps, info)?;

    // Get current config
    let mut config = get_config(deps.as_ref())?;

    // Check if the finality gadget is already in the desired state
    if config.is_enabled == enabled {
        if enabled {
            return Err(ContractError::AlreadyEnabled {});
        } else {
            return Err(ContractError::AlreadyDisabled {});
        }
    }

    // Update the enabled status in config
    config.is_enabled = enabled;
    CONFIG.save(deps.storage, &config)?;

    Result::Ok(Response::default())
}

// Helper function to check caller is contract admin
fn check_admin(deps: &DepsMut<BabylonQuery>, info: MessageInfo) -> Result<(), ContractError> {
    // Check caller is admin
    if !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}
