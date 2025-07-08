use crate::error::ContractError;
use crate::exec::admin::set_enabled;
use crate::exec::finality::handle_finality_signature;
use crate::exec::public_randomness::handle_public_randomness_commit;
use crate::msg::BabylonMsg;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::query_block_voters;
use crate::state::config::{get_config, Config, ADMIN, CONFIG, IS_ENABLED};
use crate::state::public_randomness::{get_first_pub_rand_commit, get_last_pub_rand_commit};
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};
use cw_controllers::AdminError;

pub fn instantiate(
    mut deps: DepsMut<BabylonQuery>,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Validate min_pub_rand to be at least 1
    if msg.min_pub_rand == 0 {
        return Err(ContractError::InvalidMinPubRand(msg.min_pub_rand));
    }

    let api = deps.api;
    ADMIN.set(deps.branch(), Some(api.addr_validate(&msg.admin)?))?;
    IS_ENABLED.save(deps.storage, &msg.is_enabled)?;

    let config = Config {
        bsn_id: msg.bsn_id,
        min_pub_rand: msg.min_pub_rand,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn query(
    deps: Deps<BabylonQuery>,
    _env: Env,
    msg: QueryMsg,
) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&get_config(deps)?)?),
        QueryMsg::Admin {} => Ok(to_json_binary(&ADMIN.query_admin(deps)?)?),
        QueryMsg::BlockVoters { height, hash_hex } => Ok(to_json_binary(&query_block_voters(
            deps, height, hash_hex,
        )?)?),
        QueryMsg::FirstPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &get_first_pub_rand_commit(deps.storage, &hex::decode(&btc_pk_hex)?)?,
        )?),
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &get_last_pub_rand_commit(deps.storage, &hex::decode(&btc_pk_hex)?)?,
        )?),
        QueryMsg::IsEnabled {} => Ok(to_json_binary(&IS_ENABLED.load(deps.storage)?)?),
    }
}

pub fn execute(
    deps: DepsMut<BabylonQuery>,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    let api = deps.api;

    match msg {
        ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex,
            start_height,
            num_pub_rand,
            commitment,
            signature,
        } => handle_public_randomness_commit(
            deps,
            &env,
            &fp_pubkey_hex,
            start_height,
            num_pub_rand,
            &commitment,
            &signature,
        ),
        ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex,
            l1_block_number,
            l1_block_hash_hex,
            height,
            pub_rand,
            proof,
            block_hash,
            signature,
        } => handle_finality_signature(
            deps,
            info,
            &fp_pubkey_hex,
            l1_block_number,
            l1_block_hash_hex,
            height,
            &pub_rand,
            &proof,
            &block_hash,
            &signature,
        ),
        ExecuteMsg::SetEnabled { enabled } => set_enabled(deps, info, enabled),
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, Some(api.addr_validate(&admin)?))
            .map_err(|err| match err {
                AdminError::Std(e) => ContractError::StdError(e),
                AdminError::NotAdmin {} => ContractError::Unauthorized,
            }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_env},
        OwnedDeps,
    };
    use cw_controllers::AdminResponse;

    pub(crate) const CREATOR: &str = "creator";
    pub(crate) const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

    // Define a type alias for OwnedDeps with BabylonQuery
    pub type BabylonDeps = OwnedDeps<MockStorage, MockApi, MockQuerier, BabylonQuery>;

    pub fn mock_deps_babylon() -> BabylonDeps {
        OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::default(),
            custom_query_type: PhantomData,
        }
    }

    #[test]
    fn test_update_admin() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(), // Admin provided
            bsn_id: "op-stack-l2-11155420".to_string(),
            is_enabled: true,
            min_pub_rand: 100,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Update the admin to new_admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };

        // Execute the UpdateAdmin message with non-admin info
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            non_admin_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }

    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn test_instantiate_validation(
                min_pub_rand in 0u64..1000000,
                is_enabled: bool,
                bsn_id in "[a-zA-Z0-9-_]{1,20}"
            ) {
                let mut deps = mock_deps_babylon();
                let init_admin = deps.api.addr_make(INIT_ADMIN);
                
                let msg = InstantiateMsg {
                    admin: init_admin.to_string(),
                    bsn_id: bsn_id.clone(),
                    is_enabled,
                    min_pub_rand,
                };

                let info = message_info(&deps.api.addr_make(CREATOR), &[]);
                let result = instantiate(deps.as_mut(), mock_env(), info, msg);

                // PROPERTY: "If min_pub_rand > 0, instantiate should succeed AND set state correctly"
                if min_pub_rand > 0 {
                    prop_assert!(result.is_ok(), "Expected success for min_pub_rand = {}", min_pub_rand);
                    
                    // Verify the response
                    let res = result.unwrap();
                    prop_assert_eq!(res.messages.len(), 0, "Should return no messages");
                    
                    // Verify admin was set correctly
                    ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();
                    
                    // Verify admin is queryable
                    let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
                    let admin: AdminResponse = from_json(admin_query).unwrap();
                    prop_assert_eq!(admin.admin.unwrap(), init_admin.as_str());
                    
                    // Verify config was saved correctly
                    let config_query = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
                    let config: Config = from_json(config_query).unwrap();
                    prop_assert_eq!(config.bsn_id, bsn_id);
                    prop_assert_eq!(config.min_pub_rand, min_pub_rand);
                    
                    // Verify is_enabled was saved correctly
                    let enabled_query = query(deps.as_ref(), mock_env(), QueryMsg::IsEnabled {}).unwrap();
                    let saved_enabled: bool = from_json(enabled_query).unwrap();
                    prop_assert_eq!(saved_enabled, is_enabled);
                    
                } else {
                    // PROPERTY: "If min_pub_rand = 0, instantiate should fail with specific error"
                    prop_assert!(result.is_err(), "Expected error for min_pub_rand = 0");
                    if let Err(err) = result {
                        prop_assert_eq!(err, ContractError::InvalidMinPubRand(0));
                    }
                }
            }
        }
    }
}
