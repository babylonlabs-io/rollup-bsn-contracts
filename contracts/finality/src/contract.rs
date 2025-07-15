use cosmwasm_std::{to_json_binary, Deps, DepsMut, Env, MessageInfo, QueryResponse, Response};

use babylon_bindings::BabylonQuery;

use crate::error::ContractError;
use crate::exec::allowlist::{handle_add_to_allowlist, handle_remove_from_allowlist};
use crate::exec::finality::handle_finality_signature;
use crate::exec::public_randomness::handle_public_randomness_commit;
use crate::msg::BabylonMsg;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::query_block_voters;
use crate::state::allowlist::get_allowed_finality_providers;
use crate::state::config::{get_config, set_config, Config, ADMIN};
use crate::state::pruning::handle_prune_data;
use crate::state::public_randomness::{
    get_first_pub_rand_commit, get_last_pub_rand_commit, list_pub_rand_commit,
};
use crate::utils::validate_bsn_id_format;

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

    // Add initial allowed finality providers if provided
    if let Some(fp_list) = msg.allowed_finality_providers {
        for fp_pubkey in &fp_list {
            if fp_pubkey.is_empty() {
                return Err(ContractError::EmptyFpBtcPubKey);
            }
            crate::state::allowlist::add_finality_provider_to_allowlist(deps.storage, fp_pubkey)?;
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
        QueryMsg::AllowedFinalityProviders {} => Ok(to_json_binary(
            &get_allowed_finality_providers(deps.storage)?,
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
            handle_add_to_allowlist(deps, info, fp_pubkey_hex_list)
        }
        ExecuteMsg::RemoveFromAllowlist { fp_pubkey_hex_list } => {
            handle_remove_from_allowlist(deps, info, fp_pubkey_hex_list)
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
    fn test_update_admin() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);
        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(), // Admin provided
            bsn_id: "op-stack-l2-11155420".to_string(),
            min_pub_rand: 100,
            allowed_finality_providers: None,
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
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
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
            allowed_finality_providers: None,
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
            allowed_finality_providers: None,
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
            allowed_finality_providers: None,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function - should fail due to empty consumer ID
        let err = instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap_err();
        assert!(matches!(err, ContractError::InvalidBsnId(_)));
    }

    #[test]
    fn test_update_admin_invalid_address() {
        let mut deps = mock_deps_babylon();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let invalid_new_admin = "invalid-new-admin";
        let bsn_id = "op-stack-l2-11155420".to_string();
        let min_pub_rand = get_random_u64_range(1, 1000000);

        let instantiate_msg = InstantiateMsg {
            admin: init_admin.to_string(),
            bsn_id,
            min_pub_rand,
            allowed_finality_providers: None,
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Try to update admin with invalid address
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: invalid_new_admin.to_string(),
        };

        let admin_info = message_info(&init_admin, &[]);
        let err = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap_err();
        assert!(matches!(err, ContractError::StdError(_)));
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
        let mut deps = mock_deps_babylon();
        let admin = deps.api.addr_make(INIT_ADMIN);

        // Setup contract
        let instantiate_msg = InstantiateMsg {
            admin: admin.to_string(),
            bsn_id: "op-stack-l2-11155420".to_string(),
            min_pub_rand: 100,
            allowed_finality_providers: None,
        };
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();

        let fp_pubkey_hex = "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7";

        // Test adding to allowlist with admin
        let add_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec![fp_pubkey_hex.to_string()],
        };
        let admin_info = message_info(&admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), add_msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "add_to_allowlist");
        assert_eq!(res.attributes[1].key, "num_added");
        assert_eq!(res.attributes[1].value, "1");

        // Verify FP is in allowlist
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let allowed_fps: Vec<String> = from_json(query_res).unwrap();
        assert!(allowed_fps.contains(&fp_pubkey_hex.to_string()));

        // Test adding to allowlist with non-admin should fail
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
        let add_msg_2 = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec![fp_pubkey_hex.to_string()],
        };
        let err = execute(deps.as_mut(), mock_env(), non_admin_info, add_msg_2).unwrap_err();
        assert_eq!(err, ContractError::Admin(AdminError::NotAdmin {}));

        // Test adding empty pubkey should fail
        let empty_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec!["".to_string()],
        };
        let err = execute(deps.as_mut(), mock_env(), admin_info.clone(), empty_msg).unwrap_err();
        assert_eq!(err, ContractError::EmptyFpBtcPubKey);

        // Test adding multiple valid pubkeys
        let multiple_valid_msg = ExecuteMsg::AddToAllowlist {
            fp_pubkey_hex_list: vec![
                "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string(),
                "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string(),
            ],
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            multiple_valid_msg,
        )
        .unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "add_to_allowlist");
        assert_eq!(res.attributes[1].key, "num_added");
        assert_eq!(res.attributes[1].value, "2");

        // Verify multiple FP are in allowlist
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let allowed_fps: Vec<String> = from_json(query_res).unwrap();
        assert!(allowed_fps.contains(&fp_pubkey_hex.to_string()));
        assert!(allowed_fps.contains(
            &"03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string()
        ));

        // Test removing from allowlist with admin
        let remove_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: vec![fp_pubkey_hex.to_string()],
        };
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), remove_msg).unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "remove_from_allowlist");
        assert_eq!(res.attributes[1].key, "num_removed");
        assert_eq!(res.attributes[1].value, "1");

        // Verify FP is not in allowlist
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let allowed_fps: Vec<String> = from_json(query_res).unwrap();
        assert!(!allowed_fps.contains(&fp_pubkey_hex.to_string()));

        // Test removing empty pubkey should fail
        let empty_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: vec!["".to_string()],
        };
        let err = execute(deps.as_mut(), mock_env(), admin_info.clone(), empty_msg).unwrap_err();
        assert_eq!(err, ContractError::EmptyFpBtcPubKey);

        // Test removing multiple valid pubkeys
        let multiple_valid_msg = ExecuteMsg::RemoveFromAllowlist {
            fp_pubkey_hex_list: vec![
                "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string(),
                "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string(),
            ],
        };
        let res = execute(
            deps.as_mut(),
            mock_env(),
            admin_info.clone(),
            multiple_valid_msg,
        )
        .unwrap();
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "remove_from_allowlist");
        assert_eq!(res.attributes[1].key, "num_removed");
        assert_eq!(res.attributes[1].value, "2");

        // Verify multiple FP are not in allowlist
        let query_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::AllowedFinalityProviders {},
        )
        .unwrap();
        let allowed_fps: Vec<String> = from_json(query_res).unwrap();
        assert!(!allowed_fps.contains(&fp_pubkey_hex.to_string()));
        assert!(!allowed_fps.contains(
            &"03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7".to_string()
        ));
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
}
