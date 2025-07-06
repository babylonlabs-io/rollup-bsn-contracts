use cosmwasm_std::Deps;

use babylon_bindings::{BabylonQuerier, BabylonQuery};

use crate::error::ContractError;

pub fn get_current_epoch(deps: &Deps<BabylonQuery>) -> Result<u64, ContractError> {
    // Use a Custom query to query the current Babylon epoch
    let bq = BabylonQuerier::new(&deps.querier);
    let current_epoch = bq.current_epoch()?;
    Ok(current_epoch.u64())
}

pub fn get_last_finalized_epoch(deps: &Deps<BabylonQuery>) -> Result<u64, ContractError> {
    // Use custom query to query the last finalized Babylon epoch
    let bq = BabylonQuerier::new(&deps.querier);
    let last_finalized_epoch = bq.latest_finalized_epoch_info()?;

    Ok(last_finalized_epoch.epoch_number)
}
