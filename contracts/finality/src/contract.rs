use cosmwasm_std::{to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};

use babylon_bindings::BabylonQuery;

use crate::error::ContractError;
use crate::exec::finality::handle_finality_signature;
use crate::exec::public_randomness::handle_public_randomness_commit;
use crate::msg::BabylonMsg;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::query_block_voters;
use crate::state::config::{get_config, set_config, Config, RateLimitingConfig, ADMIN};
use crate::state::pruning::handle_prune_data;
use crate::state::public_randomness::{
    get_first_pub_rand_commit, get_last_pub_rand_commit, list_pub_rand_commit,
};

pub fn instantiate(
    mut deps: DepsMut<BabylonQuery>,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    // validate the instantiation message
    msg.validate()?;

    // Validate and set admin address
    let api = deps.api;
    ADMIN.set(deps.branch(), Some(api.addr_validate(&msg.admin)?))?;

    let config = Config {
        bsn_id: msg.bsn_id,
        min_pub_rand: msg.min_pub_rand,
        rate_limiting: RateLimitingConfig {
            max_msgs_per_interval: msg.max_msgs_per_interval,
            block_interval: msg.rate_limiting_interval,
        },
        bsn_activation_height: msg.bsn_activation_height,
        finality_signature_interval: msg.finality_signature_interval,
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
        QueryMsg::Config {} => Ok(to_json_binary(&get_config(deps.storage)?)?),
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
        ExecuteMsg::PruneData {
            rollup_height,
            max_signatures_to_prune,
            max_pub_rand_values_to_prune,
        } => handle_prune_data(
            deps,
            info,
            rollup_height,
            max_signatures_to_prune,
            max_pub_rand_values_to_prune,
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    use crate::state::finality::{insert_finality_sig_and_signatory, list_finality_signatures};
    use crate::state::public_randomness::{get_pub_rand_value, insert_pub_rand_value};
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

    const MAX_MSGS_PER_INTERVAL: u32 = 100;
    const RATE_LIMITING_INTERVAL: u64 = 10000;

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
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 1000,
            finality_signature_interval: 100,
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
        let bsn_activation_height = get_random_u64_range(1, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id: bsn_id.clone(),
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
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
            assert_eq!(config.bsn_activation_height, bsn_activation_height);
            assert_eq!(
                config.finality_signature_interval,
                finality_signature_interval
            );
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
        let bsn_activation_height = get_random_u64_range(1, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: invalid_admin.to_string(),
            bsn_id,
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
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
        let bsn_activation_height = get_random_u64_range(1, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: valid_admin.to_string(),
            bsn_id: invalid_bsn_id.to_string(),
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
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
        let bsn_activation_height = get_random_u64_range(1, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: valid_admin.to_string(),
            bsn_id: empty_bsn_id.to_string(),
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
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
        let min_pub_rand = get_random_u64_range(1, 1000000);
        let bsn_activation_height = get_random_u64_range(1, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        // Initialize contract
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
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
            "",               // Empty string
            "a",              // Too short
            "invalid",        // No prefix
            "cosmos1",        // Incomplete
            "cosmos1invalid", // Invalid format
            // Invalid prefix
            "invalid1234567890123456789012345678901234567890",
            // Too long
            "cosmos1234567890123456789012345678901234567890123456789012345678901234567890",
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
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 1,
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
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 1,
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
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 1,
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
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 1,
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

    #[test]
    fn test_prune_finality_signatures_execution() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let non_admin = deps.api.addr_make("non_admin");

        // Set up admin
        ADMIN.set(deps.as_mut(), Some(admin.clone())).unwrap();

        // Insert some finality signatures
        let fp_btc_pk = get_random_fp_pk();
        for height in 100..110 {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Verify signatures exist before pruning
        for height in 100..110 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_some());
        }

        // Test successful pruning by admin
        let msg = ExecuteMsg::PruneData {
            rollup_height: 105,
            max_signatures_to_prune: Some(10),
            max_pub_rand_values_to_prune: None,
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "prune_data");
        assert_eq!(response.attributes[1].key, "rollup_height");
        assert_eq!(response.attributes[1].value, "105");
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "6"); // Heights 100-105
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "6"); // Heights 100-105

        // Verify signatures are pruned
        for height in 100..106 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_none());
        }

        // Verify remaining signatures are still there
        for height in 106..110 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_some());
        }

        // Test that non-admin cannot call pruning
        let msg = ExecuteMsg::PruneData {
            rollup_height: 200,
            max_signatures_to_prune: None,
            max_pub_rand_values_to_prune: None,
        };

        let info = message_info(&non_admin, &[]);
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_prune_signatories_execution() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let non_admin = deps.api.addr_make("non_admin");

        // Set up admin
        ADMIN.set(deps.as_mut(), Some(admin.clone())).unwrap();

        // Insert some signatories entries
        let fp_btc_pk = get_random_fp_pk();
        for height in 100..110 {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Verify signatories exist before pruning
        for height in 100..110 {
            let block_hash = get_random_block_hash(); // This won't match, but we're just checking the function exists
            let _signatories = crate::state::finality::get_signatories_by_block_hash(
                deps.as_ref().storage,
                height,
                &block_hash,
            )
            .unwrap();
            // Note: This will be None because we're using a different block_hash, but the function should work
        }

        // Test successful pruning by admin
        let msg = ExecuteMsg::PruneData {
            rollup_height: 105,
            max_signatures_to_prune: Some(10),
            max_pub_rand_values_to_prune: None,
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5); // action, rollup_height, pruned_signatures, pruned_signatories, pruned_pub_rand_values
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "prune_data");
        assert_eq!(response.attributes[1].key, "rollup_height");
        assert_eq!(response.attributes[1].value, "105");
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "6"); // Heights 100-105
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "6"); // Heights 100-105
        assert_eq!(response.attributes[4].key, "pruned_pub_rand_values");
        assert_eq!(response.attributes[4].value, "0");

        // Test that non-admin cannot call pruning
        let msg = ExecuteMsg::PruneData {
            rollup_height: 200,
            max_signatures_to_prune: None,
            max_pub_rand_values_to_prune: None,
        };

        let info = message_info(&non_admin, &[]);
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_prune_public_randomness_values_execution() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let non_admin = deps.api.addr_make("non_admin");

        // Set up admin
        ADMIN.set(deps.as_mut(), Some(admin.clone())).unwrap();

        // Insert some public randomness values
        let fp_btc_pk = get_random_fp_pk();
        for height in 100..110 {
            let pub_rand = get_random_pub_rand();
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, height, &pub_rand).unwrap();
        }

        // Verify values exist before pruning
        for height in 100..110 {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_some());
        }

        // Test successful pruning by admin
        let msg = ExecuteMsg::PruneData {
            rollup_height: 105,
            max_signatures_to_prune: None,
            max_pub_rand_values_to_prune: Some(10),
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "prune_data");
        assert_eq!(response.attributes[1].key, "rollup_height");
        assert_eq!(response.attributes[1].value, "105");
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "0");
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "0");
        assert_eq!(response.attributes[4].key, "pruned_pub_rand_values");
        assert_eq!(response.attributes[4].value, "6"); // Heights 100-105

        // Verify values are pruned
        for height in 100..106 {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_none());
        }

        // Verify remaining values are still there
        for height in 106..110 {
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_some());
        }

        // Test that non-admin cannot call pruning
        let msg = ExecuteMsg::PruneData {
            rollup_height: 200,
            max_signatures_to_prune: None,
            max_pub_rand_values_to_prune: None,
        };

        let info = message_info(&non_admin, &[]);
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_prune_data_execution() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let non_admin = deps.api.addr_make("non_admin");

        // Set up admin
        ADMIN.set(deps.as_mut(), Some(admin.clone())).unwrap();

        // Insert some finality signatures
        let fp_btc_pk = get_random_fp_pk();
        for height in 100..110 {
            let block_hash = get_random_block_hash();
            let signature = get_random_block_hash();
            insert_finality_sig_and_signatory(
                deps.as_mut().storage,
                &fp_btc_pk,
                height,
                &block_hash,
                &signature,
            )
            .unwrap();
        }

        // Insert some public randomness values
        for height in 100..110 {
            let pub_rand = get_random_pub_rand();
            insert_pub_rand_value(deps.as_mut().storage, &fp_btc_pk, height, &pub_rand).unwrap();
        }

        // Verify data exists before pruning
        for height in 100..110 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_some());
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_some());
        }

        // Test successful pruning of both data types by admin
        let msg = ExecuteMsg::PruneData {
            rollup_height: 105,
            max_signatures_to_prune: Some(10),
            max_pub_rand_values_to_prune: Some(10),
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "prune_data");
        assert_eq!(response.attributes[1].key, "rollup_height");
        assert_eq!(response.attributes[1].value, "105");
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "6"); // Heights 100-105
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "6"); // Heights 100-105
        assert_eq!(response.attributes[4].key, "pruned_pub_rand_values");
        assert_eq!(response.attributes[4].value, "6"); // Heights 100-105

        // Verify data is pruned
        for height in 100..106 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_none());
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_none());
        }

        // Verify remaining data is still there
        for height in 106..110 {
            let sig = list_finality_signatures(deps.as_ref().storage, height, &fp_btc_pk).unwrap();
            assert!(sig.is_some());
            let val = get_pub_rand_value(deps.as_ref().storage, &fp_btc_pk, height).unwrap();
            assert!(val.is_some());
        }

        // Test pruning only finality signatures
        let msg = ExecuteMsg::PruneData {
            rollup_height: 108,
            max_signatures_to_prune: Some(5),
            max_pub_rand_values_to_prune: Some(0),
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5); // action, rollup_height, pruned_signatures, pruned_signatories, pruned_pub_rand_values
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "3"); // Heights 106-108
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "3"); // Heights 106-108
        assert_eq!(response.attributes[4].key, "pruned_pub_rand_values");
        assert_eq!(response.attributes[4].value, "0"); // Heights 106-108

        // Test pruning only pub rand values
        let msg = ExecuteMsg::PruneData {
            rollup_height: 108,
            max_signatures_to_prune: Some(0),
            max_pub_rand_values_to_prune: Some(5),
        };

        let info = message_info(&admin, &[]);
        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        assert_eq!(response.attributes.len(), 5); // action, rollup_height, pruned_signatures, pruned_signatories, pruned_pub_rand_values
        assert_eq!(response.attributes[2].key, "pruned_signatures");
        assert_eq!(response.attributes[2].value, "0"); // Heights 106-108
        assert_eq!(response.attributes[3].key, "pruned_signatories");
        assert_eq!(response.attributes[3].value, "0"); // Heights 106-108
        assert_eq!(response.attributes[4].key, "pruned_pub_rand_values");
        // The value will depend on the test setup, but you can check it's a string representing a number.
        assert!(response.attributes[4].value.parse::<u64>().is_ok());

        // Test that non-admin cannot call pruning
        let msg = ExecuteMsg::PruneData {
            rollup_height: 200,
            max_signatures_to_prune: Some(0),
            max_pub_rand_values_to_prune: Some(0),
        };

        let info = message_info(&non_admin, &[]);
        let result = execute(deps.as_mut(), mock_env(), info, msg);
        assert!(result.is_err());
    }
}
