use cosmwasm_std::{DepsMut, MessageInfo, Response};

use babylon_bindings::BabylonQuery;

use crate::state::config::ADMIN;
use crate::BabylonMsg;
use crate::ContractError;

/// The maximum number of items to prune in a single operation.
pub(crate) const MAX_PRUNING: u32 = 100;

/// The default number of items to prune in a single operation.
pub(crate) const DEFAULT_PRUNING: u32 = 50;

/// Handles the pruning of data from the contract.
///
/// This function prunes finality signatures, signatories by block hash, and public randomness values for rollup blocks with height <= rollup_height.
/// It's designed to be called manually by the admin to prevent indefinite storage growth.
pub(crate) fn handle_prune_data(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    rollup_height: u64,
    max_signatures_to_prune: Option<u32>,
    max_signatories_to_prune: Option<u32>,
    max_pub_rand_values_to_prune: Option<u32>,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure only admin can call this
    ADMIN.assert_admin(deps.as_ref(), &info.sender)?;

    let mut response = Response::new()
        .add_attribute("action", "prune_data")
        .add_attribute("rollup_height", rollup_height.to_string());

    // Prune finality signatures
    let pruned_signatures = crate::state::finality::prune_finality_signatures(
        deps.storage,
        rollup_height,
        max_signatures_to_prune,
    )?;
    response = response.add_attribute("pruned_signatures", pruned_signatures.to_string());

    // Prune signatories by block hash
    let pruned_signatories = crate::state::finality::prune_signatories_by_block_hash(
        deps.storage,
        rollup_height,
        max_signatories_to_prune,
    )?;
    response = response.add_attribute("pruned_signatories", pruned_signatories.to_string());

    // Prune public randomness values
    let pruned_values = crate::state::public_randomness::prune_public_randomness_values(
        deps.storage,
        rollup_height,
        max_pub_rand_values_to_prune,
    )?;
    response = response.add_attribute("pruned_pub_rand_values", pruned_values.to_string());

    Ok(response)
}
