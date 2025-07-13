use crate::error::ContractError;
use crate::exec::finality::handle_finality_signature;
use crate::exec::public_randomness::handle_public_randomness_commit;
use crate::msg::BabylonMsg;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::query_block_voters;
use crate::state::config::{get_config, set_config, Config, ADMIN};
use crate::state::public_randomness::{
    get_first_pub_rand_commit, get_last_pub_rand_commit, list_pub_rand_commit,
};
use crate::utils::validate_bsn_id_format;
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};

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

    // Validate and set admin address
    ADMIN.set(deps.branch(), Some(api.addr_validate(&msg.admin)?))?;

    // Validate consumer ID format
    validate_bsn_id_format(&msg.bsn_id)?;

    let config = Config {
        bsn_id: msg.bsn_id,
        min_pub_rand: msg.min_pub_rand,
    };
    set_config(deps.storage, &config)?;

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
        QueryMsg::ListPubRandCommit {
            btc_pk_hex,
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(&list_pub_rand_commit(
            deps.storage,
            &hex::decode(&btc_pk_hex)?,
            start_after,
            limit,
            reverse,
        )?)?),
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
            &env,
            &fp_pubkey_hex,
            l1_block_number,
            l1_block_hash_hex,
            height,
            &pub_rand,
            &proof,
            &block_hash,
            &signature,
        ),
        ExecuteMsg::UpdateAdmin { admin } => {
            // Validate and set the new admin address
            Ok(ADMIN.execute_update_admin(deps, info, Some(api.addr_validate(&admin)?))?)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    use crate::testutil::datagen::*;
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
        from_json,
        testing::{message_info, mock_env},
        OwnedDeps,
    };
    use cw_controllers::{AdminError, AdminResponse};

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
    fn test_only_admin_can_update_admin() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        let random_user = deps.api.addr_make("random_user");
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 1: Only admin can update admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };

        // Random user should fail
        let random_info = message_info(&random_user, &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            random_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));

        // Creator should fail (not admin)
        let creator_info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            creator_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));

        // Current admin should succeed
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Verify admin was updated
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }

    #[test]
    fn test_instantiate_validation() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        let min_pub_rand = get_random_u64_range(0, 1000000);
        let bsn_id = "op-stack-l2-11155420".to_string();

        let msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id: bsn_id.clone(),
            min_pub_rand,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let result = instantiate(deps.as_mut(), mock_env(), info, msg);

        if min_pub_rand > 0 {
            // Should succeed and set state correctly
            assert!(
                result.is_ok(),
                "Expected success for min_pub_rand = {min_pub_rand}"
            );

            // Verify the response
            let res = result.unwrap();
            assert_eq!(res.messages.len(), 0);

            // Verify admin was set correctly
            ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

            // Verify admin is queryable
            let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
            let admin: AdminResponse = from_json(admin_query).unwrap();
            assert_eq!(admin.admin.unwrap(), init_admin.as_str());

            // Verify config was saved correctly
            let config_query = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
            let config: Config = from_json(config_query).unwrap();
            assert_eq!(config.bsn_id, bsn_id);
            assert_eq!(config.min_pub_rand, min_pub_rand);
        } else {
            // Should fail with specific error
            assert!(result.is_err(), "Expected error for min_pub_rand = 0");
            assert_eq!(result.unwrap_err(), ContractError::InvalidMinPubRand(0));
        }
    }

    #[test]
    fn test_invalid_admin_address() {
        let mut deps = mock_deps_babylon();
        let invalid_admin = "invalid-address";
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: invalid_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to invalid admin address
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::StdError(_)));
    }

    #[test]
    fn test_invalid_consumer_id() {
        let mut deps = mock_deps_babylon();
        let valid_admin = deps.api.addr_make(INIT_ADMIN);
        let invalid_bsn_id = "invalid@bsn#id"; // Contains invalid characters
        let min_pub_rand = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: valid_admin.to_string(),
            bsn_id: invalid_bsn_id.to_string(),
            min_pub_rand,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to invalid consumer ID
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_empty_consumer_id() {
        let mut deps = mock_deps_babylon();
        let valid_admin = deps.api.addr_make(INIT_ADMIN);
        let empty_bsn_id = "";
        let min_pub_rand = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: valid_admin.to_string(),
            bsn_id: empty_bsn_id.to_string(),
            min_pub_rand,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to empty consumer ID
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_admin_update_rejects_malformed_addresses() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        let admin_info = message_info(&init_admin, &[]);

        // Test various invalid address formats
        let invalid_addresses = vec![
            "",                                                // Empty string
            "a",                                               // Too short
            "invalid",                                         // No prefix
            "cosmos1",                                         // Incomplete
            "cosmos1invalid",                                  // Invalid format
            "invalid1234567890123456789012345678901234567890", // Invalid prefix
            "cosmos1234567890123456789012345678901234567890123456789012345678901234567890", // Too long
            "COSMOS1INVALIDUPPERCASE", // Uppercase (should be lowercase)
            "cosmos1!@#$%^&*()",       // Special characters
            "cosmos1\n\t\r",           // Control characters
            "cosmos1 space",           // Contains space
            "cosmos1-dash",            // Contains dash
            "cosmos1.dot",             // Contains dot
        ];

        for invalid_addr in invalid_addresses {
            let update_admin_msg = ExecuteMsg::UpdateAdmin {
                admin: invalid_addr.to_string(),
            };
            let err = execute(
                deps.as_mut(),
                mock_env(),
                admin_info.clone(),
                update_admin_msg,
            )
            .unwrap_err();
            assert!(
                matches!(err, ContractError::StdError(_)),
                "Expected StdError for invalid address: {}",
                invalid_addr
            );
        }

        // Test valid addresses should work
        let valid_new_admin = deps.api.addr_make("valid_admin");
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: valid_new_admin.to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        ADMIN.assert_admin(deps.as_ref(), &valid_new_admin).unwrap();
    }

    #[test]
    fn test_admin_query_returns_correct_admin_after_updates() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        let third_admin = deps.api.addr_make("third_admin");
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 1: Initial admin query
        let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin_response: AdminResponse = from_json(admin_query).unwrap();
        assert_eq!(admin_response.admin.unwrap(), init_admin.as_str());

        // Test 2: Update admin and verify query consistency
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };
        let admin_info = message_info(&init_admin, &[]);
        execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Query should reflect the new admin
        let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin_response: AdminResponse = from_json(admin_query).unwrap();
        assert_eq!(admin_response.admin.unwrap(), new_admin.as_str());

        // Test 3: Multiple updates and consistency
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: third_admin.to_string(),
        };
        let admin_info = message_info(&new_admin, &[]);
        execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin_response: AdminResponse = from_json(admin_query).unwrap();
        assert_eq!(admin_response.admin.unwrap(), third_admin.as_str());

        // Test 4: Verify old admin cannot update anymore
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: init_admin.to_string(),
        };
        let old_admin_info = message_info(&init_admin, &[]);
        let err = execute(deps.as_mut(), mock_env(), old_admin_info, update_admin_msg).unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));
    }

    #[test]
    fn test_admin_update_idempotency() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 1: Setting admin to same value should work
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: init_admin.to_string(),
        };
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            update_admin_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        // Admin should still be the same
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 2: Update to new admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();

        // Test 3: Setting new admin to same value should work
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };
        let admin_info = message_info(&new_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }

    #[test]
    fn test_admin_permissions_transfer_immediately_after_update() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 1: Admin can update to themselves (idempotent)
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: init_admin.to_string(),
        };
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            update_admin_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        // Test 2: Admin transfers to new admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            update_admin_msg,
        )
        .unwrap();
        assert_eq!(0, res.messages.len());

        // Test 3: Old admin loses permissions immediately
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: init_admin.to_string(),
        };
        let err = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));

        // Test 4: New admin has full permissions
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: init_admin.to_string(),
        };
        let new_admin_info = message_info(&new_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), new_admin_info, update_admin_msg).unwrap();
        assert_eq!(0, res.messages.len());
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();
    }

    #[test]
    fn test_admin_state_persists_across_queries_and_updates() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = 100;

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());
        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Test 1: Admin state persists across queries
        for _ in 0..5 {
            let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
            let admin_response: AdminResponse = from_json(admin_query).unwrap();
            assert_eq!(admin_response.admin.unwrap(), init_admin.as_str());
        }

        // Test 2: Admin state persists after update
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: new_admin.to_string(),
        };
        let admin_info = message_info(&init_admin, &[]);
        execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Verify persistence across multiple queries
        for _ in 0..5 {
            let admin_query = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
            let admin_response: AdminResponse = from_json(admin_query).unwrap();
            assert_eq!(admin_response.admin.unwrap(), new_admin.as_str());
        }

        // Test 3: Config should remain unchanged after admin update
        let config_query = query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap();
        let config: Config = from_json(config_query).unwrap();
        assert_eq!(config.bsn_id, "op-stack-l2-11155420".to_string());
        assert_eq!(config.min_pub_rand, min_pub_rand);
    }
}
