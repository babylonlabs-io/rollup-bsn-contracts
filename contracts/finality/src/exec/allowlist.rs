use cosmwasm_std::{DepsMut, MessageInfo, Response};

use babylon_bindings::BabylonQuery;

use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::config::ADMIN;

/// Handle adding finality providers to the allowlist
pub fn handle_add_to_allowlist(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    fp_pubkey_hex_list: Vec<String>,
) -> Result<Response<BabylonMsg>, ContractError> {
    if fp_pubkey_hex_list.is_empty() {
        return Err(ContractError::EmptyFpBtcPubKey);
    }

    // Validate all public keys are not empty
    for key in &fp_pubkey_hex_list {
        if key.is_empty() {
            return Err(ContractError::EmptyFpBtcPubKey);
        }
    }

    ADMIN.assert_admin(deps.as_ref(), &info.sender)?;

    for key in &fp_pubkey_hex_list {
        let fp_btc_pk_bytes = hex::decode(key)?;
        crate::state::allowlist::add_finality_provider_to_allowlist(
            deps.storage,
            &fp_btc_pk_bytes,
        )?;
    }

    Ok(Response::new()
        .add_attribute("action", "add_to_allowlist")
        .add_attribute("num_added", fp_pubkey_hex_list.len().to_string()))
}

/// Handle removing finality providers from the allowlist
pub fn handle_remove_from_allowlist(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    fp_pubkey_hex_list: Vec<String>,
) -> Result<Response<BabylonMsg>, ContractError> {
    if fp_pubkey_hex_list.is_empty() {
        return Err(ContractError::EmptyFpBtcPubKey);
    }

    // Validate all public keys are not empty
    for key in &fp_pubkey_hex_list {
        if key.is_empty() {
            return Err(ContractError::EmptyFpBtcPubKey);
        }
    }

    ADMIN.assert_admin(deps.as_ref(), &info.sender)?;

    for key in &fp_pubkey_hex_list {
        let fp_btc_pk_bytes = hex::decode(key)?;
        crate::state::allowlist::remove_finality_provider_from_allowlist(
            deps.storage,
            &fp_btc_pk_bytes,
        )?;
    }

    Ok(Response::new()
        .add_attribute("action", "remove_from_allowlist")
        .add_attribute("num_removed", fp_pubkey_hex_list.len().to_string()))
}
