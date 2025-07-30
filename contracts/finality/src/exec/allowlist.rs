use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

use crate::error::ContractError;
use crate::msg::BabylonMsg;
use crate::state::allowlist::{
    add_finality_providers_to_allowlist, remove_finality_providers_from_allowlist,
};
use crate::state::config::ADMIN;
use babylon_bindings::BabylonQuery;

/// Handle adding finality providers to the allowlist
pub fn handle_add_to_allowlist(
    deps: DepsMut<BabylonQuery>,
    env: Env,
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

    // Convert hex strings to bytes
    let mut fp_btc_pk_bytes_list = Vec::new();
    for key in &fp_pubkey_hex_list {
        let fp_btc_pk_bytes = hex::decode(key)?;
        fp_btc_pk_bytes_list.push(fp_btc_pk_bytes);
    }

    add_finality_providers_to_allowlist(deps.storage, &fp_btc_pk_bytes_list, env.block.height)?;

    Ok(Response::new()
        .add_attribute("action", "add_to_allowlist")
        .add_attribute("num_added", fp_pubkey_hex_list.len().to_string()))
}

/// Handle removing finality providers from the allowlist
pub fn handle_remove_from_allowlist(
    deps: DepsMut<BabylonQuery>,
    env: Env,
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

    // Convert hex strings to bytes and collect into slice references
    let mut fp_btc_pk_bytes_list = Vec::new();
    for key in &fp_pubkey_hex_list {
        let fp_btc_pk_bytes = hex::decode(key)?;
        fp_btc_pk_bytes_list.push(fp_btc_pk_bytes);
    }

    remove_finality_providers_from_allowlist(
        deps.storage,
        &fp_btc_pk_bytes_list,
        env.block.height,
    )?;

    Ok(Response::new()
        .add_attribute("action", "remove_from_allowlist")
        .add_attribute("num_removed", fp_pubkey_hex_list.len().to_string()))
}
