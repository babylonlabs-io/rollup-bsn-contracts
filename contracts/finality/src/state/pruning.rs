use cosmwasm_std::{DepsMut, MessageInfo, Response};

use babylon_bindings::BabylonQuery;

use crate::state::config::ADMIN;
use crate::BabylonMsg;
use crate::ContractError;

pub(crate) fn handle_prune_data(
    deps: DepsMut<BabylonQuery>,
    info: MessageInfo,
    rollup_height: u64,
    max_signatures_to_prune: Option<u32>,
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

    // Prune public randomness values
    let pruned_values = crate::state::public_randomness::prune_public_randomness_values(
        deps.storage,
        rollup_height,
        max_pub_rand_values_to_prune,
    )?;
    response = response.add_attribute("pruned_pub_rand_values", pruned_values.to_string());

    Ok(response)
}
