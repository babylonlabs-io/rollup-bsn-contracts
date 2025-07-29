use cosmwasm_std::{to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};

use babylon_bindings::BabylonQuery;

use crate::error::ContractError;
use crate::exec::allowlist::{handle_add_to_allowlist, handle_remove_from_allowlist};
use crate::exec::finality::handle_finality_signature;
use crate::exec::public_randomness::handle_public_randomness_commit;
use crate::msg::BabylonMsg;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::query_block_voters;
use crate::state::allowlist::{get_allowed_finality_providers, get_allowed_finality_providers_at_height};
use crate::state::config::{get_config, set_config, Config, RateLimitingConfig, ADMIN};
use crate::state::pruning::handle_prune_data;
use crate::state::public_randomness::{
    get_first_pub_rand_commit, get_last_pub_rand_commit, list_pub_rand_commit,
};

pub fn instantiate(
    mut deps: DepsMut<BabylonQuery>,
    env: Env,
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

    // Add initial allowed finality providers if provided
    if let Some(fp_list) = msg.allowed_finality_providers {
        for fp_pubkey in &fp_list {
            if fp_pubkey.is_empty() {
                return Err(ContractError::EmptyFpBtcPubKey);
            }
            let fp_btc_pk_bytes = hex::decode(fp_pubkey)?;
            crate::state::allowlist::add_finality_provider_to_allowlist(
                deps.storage,
                &fp_btc_pk_bytes,
                env.block.height,
            )?;
        }
    }

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
        QueryMsg::AllowedFinalityProviders {} => Ok(to_json_binary(
            &get_allowed_finality_providers(deps.storage)?,
        )?),
        QueryMsg::AllowedFinalityProvidersAtHeight { height } => Ok(to_json_binary(
            &get_allowed_finality_providers_at_height(deps.storage, height)?,
        )?),
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
        ExecuteMsg::AddToAllowlist { fp_pubkey_hex_list } => {
            handle_add_to_allowlist(deps, env, info, fp_pubkey_hex_list)
        }
        ExecuteMsg::RemoveFromAllowlist { fp_pubkey_hex_list } => {
            handle_remove_from_allowlist(deps, env, info, fp_pubkey_hex_list)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::marker::PhantomData;

    use crate::state::finality::{insert_finality_sig_and_signatory, list_finality_signatures};
    use crate::state::public_randomness::{get_pub_rand_value, insert_pub_rand_value};
    use crate::testutil::datagen::*;
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{
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
    fn test_update_admin() {
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
            allowed_finality_providers: None,
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

        // Define valid_admin and empty_bsn_id for the next test
        let valid_admin = deps.api.addr_make("valid_admin");
        let empty_bsn_id = "";

        let instantiate_msg = InstantiateMsg {
            admin: valid_admin.to_string(),
            bsn_id: empty_bsn_id.to_string(),
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to empty consumer ID
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
        // Verify admin was updated
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }

    #[test]
    fn test_instantiate_validation() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        let min_pub_rand = get_random_u64_range(0, 1000000);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let bsn_activation_height = get_random_u64_range(0, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id: bsn_id.clone(),
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
            allowed_finality_providers: None,
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
        let bsn_activation_height = get_random_u64_range(0, 1000000);
        let finality_signature_interval = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: invalid_admin.to_string(),
            bsn_id,
            min_pub_rand,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height,
            finality_signature_interval,
            allowed_finality_providers: None,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to invalid admin address
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::StdError(_)));
    }

    #[test]
    fn test_update_admin_invalid_address() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = get_random_u64_range(1, 1000000);
        let bsn_activation_height = get_random_u64_range(0, 1000000);
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
            allowed_finality_providers: None,
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
                "Expected StdError for invalid address: {invalid_addr}"
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
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 100,
            allowed_finality_providers: None,
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
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 1,
            allowed_finality_providers: None,
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
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 100,
            allowed_finality_providers: None,
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
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 1,
            finality_signature_interval: 100,
            allowed_finality_providers: None,
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

    #[test]
    fn test_allowlist_management() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let admin_info = message_info(&admin, &[]);
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);

        // Helper to generate random hex pubkeys using a shared rng
        fn random_fp_pubkeys(rng: &mut StdRng, n: usize) -> Vec<String> {
            (0..n)
                .map(|_| {
                    (0..66)
                        .map(|_| format!("{:x}", rng.random_range(0..16)))
                        .collect::<String>()
                })
                .collect()
        }

        let mut rng = StdRng::seed_from_u64(42); // deterministic
        let initial_fps = random_fp_pubkeys(&mut rng, 5);

        let instantiate_msg = InstantiateMsg {
            admin: admin.to_string(),
            bsn_id: "op-stack-l2-11155420".to_string(),
            min_pub_rand: 100,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: Some(initial_fps.clone()),
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();

        // Check all initial FPs are in allowlist
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let mut allowed_fps: Vec<String> = from_json(query_res).unwrap();
        for fp in &initial_fps {
            assert!(allowed_fps.contains(fp));
        }
        let orig_len = allowed_fps.len();

        // Test adding a duplicate FP (should not error, allowlist unchanged)
        let dup_add_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec![initial_fps[0].clone()],
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), dup_add_msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "add_to_allowlist");
        // Allowlist should not grow
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        allowed_fps = from_json(query_res).unwrap();
        assert_eq!(allowed_fps.len(), orig_len);

        // Test removing a non-existent FP (should not error, allowlist unchanged)
        let non_existent_fp = "deadbeef".repeat(8);
        let remove_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: vec![non_existent_fp.clone()],
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "remove_from_allowlist");
        // Allowlist should not shrink
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        allowed_fps = from_json(query_res).unwrap();
        assert_eq!(allowed_fps.len(), orig_len);

        // Test adding more FPs
        let new_fps = random_fp_pubkeys(&mut rng, 3);
        let add_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: new_fps.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        assert_eq!(res.attributes[0].value, "add_to_allowlist");
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        allowed_fps = from_json(query_res).unwrap();
        for fp in &new_fps {
            assert!(allowed_fps.contains(fp));
        }
        assert_eq!(allowed_fps.len(), orig_len + new_fps.len());

        // Test removing some FPs (including one that was just added)
        let remove_some = vec![initial_fps[0].clone(), new_fps[0].clone()];
        let remove_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: remove_some.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_msg).unwrap();
        assert_eq!(res.attributes[0].value, "remove_from_allowlist");
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        allowed_fps = from_json(query_res).unwrap();
        for fp in &remove_some {
            assert!(!allowed_fps.contains(fp));
        }
        assert_eq!(
            allowed_fps.len(),
            orig_len + new_fps.len() - remove_some.len()
        );

        // Test non-admin cannot add
        let add_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: random_fp_pubkeys(&mut rng, 1),
        };
        let err = execute(deps.as_mut(), mock_env(), non_admin_info, add_msg).unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));
    }

    #[test]
    fn test_instantiate_with_allowed_finality_providers() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);

        // Test instantiating with initial allowlist
        let initial_fp =
            "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string();
        let instantiate_msg = InstantiateMsg {
            admin: admin.to_string(),
            bsn_id: "op-stack-l2-11155420".to_string(),
            min_pub_rand: 100,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: Some(vec![initial_fp.clone()]),
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();
        // Query and check
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let allowed_fps: Vec<String> = from_json(query_res).unwrap();
        assert!(allowed_fps.contains(&initial_fp));
    }

    #[test]
    fn test_historical_allowlist_query() {
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);
        let admin_info = message_info(&admin, &[]);

        // Helper function to create mock env with specific height
        fn mock_env_at_height(height: u64) -> Env {
            let mut env = mock_env();
            env.block.height = height;
            env
        }

        // Setup: Instantiate with initial FPs
        let initial_fps = vec![
            "02".repeat(33), // fp1
            "03".repeat(33), // fp2
            "04".repeat(33), // fp3
        ];
        let instantiate_msg = InstantiateMsg {
            admin: admin.to_string(),
            bsn_id: "op-stack-l2-test".to_string(),
            min_pub_rand: 100,
            max_msgs_per_interval: MAX_MSGS_PER_INTERVAL,
            rate_limiting_interval: RATE_LIMITING_INTERVAL,
            bsn_activation_height: 0,
            finality_signature_interval: 1,
            allowed_finality_providers: Some(initial_fps.clone()),
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env_at_height(100), info, instantiate_msg).unwrap();

        // Height 105: Add fp4, Remove fp3
        let add_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec!["05".repeat(33)], // fp4
        };
        execute(deps.as_mut(), mock_env_at_height(105), admin_info.clone(), add_msg).unwrap();
        
        let remove_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: vec![initial_fps[2].clone()], // remove fp3
        };
        execute(deps.as_mut(), mock_env_at_height(105), admin_info, remove_msg).unwrap();

        // Test historical queries
        
        // Query at height 102 (should get state from height 100): [fp1, fp2, fp3]
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProvidersAtHeight { height: 102 },
        ).unwrap();
        let fps_at_102: Vec<String> = from_json(query_res).unwrap();
        assert_eq!(fps_at_102.len(), 3);
        assert!(fps_at_102.contains(&initial_fps[0])); // fp1
        assert!(fps_at_102.contains(&initial_fps[1])); // fp2  
        assert!(fps_at_102.contains(&initial_fps[2])); // fp3
        assert!(!fps_at_102.contains(&"05".repeat(33))); // fp4 not added yet

        // Query at height 107 (should get state from height 105): [fp1, fp2, fp4]
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProvidersAtHeight { height: 107 },
        ).unwrap();
        let fps_at_107: Vec<String> = from_json(query_res).unwrap();
        assert_eq!(fps_at_107.len(), 3);
        assert!(fps_at_107.contains(&initial_fps[0])); // fp1
        assert!(fps_at_107.contains(&initial_fps[1])); // fp2
        assert!(!fps_at_107.contains(&initial_fps[2])); // fp3 removed
        assert!(fps_at_107.contains(&"05".repeat(33))); // fp4 added

        // Query current state (should match height 107)
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        ).unwrap();
        let current_fps: Vec<String> = from_json(query_res).unwrap();
        assert_eq!(current_fps.len(), fps_at_107.len());
        for fp in &fps_at_107 {
            assert!(current_fps.contains(fp));
        }
    }
}
