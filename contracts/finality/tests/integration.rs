use cosmwasm_std::{from_json, Coin, ContractResult, Response};
use cosmwasm_vm::testing::{
    instantiate, mock_env, mock_info, mock_instance_with_options, query, MockApi,
    MockInstanceOptions, MockQuerier, MockStorage,
};
use cosmwasm_vm::{capabilities_from_csv, Instance};

use cw_controllers::AdminResponse;
use finality::msg::{InstantiateMsg, QueryMsg};
use finality::state::config::Config;

static WASM: &[u8] = include_bytes!("../../../artifacts/finality.wasm");
const CREATOR: &str = "creator";

fn mock_instance_on_babylon(
    wasm: &[u8],
    funds: &[Coin],
) -> Instance<MockApi, MockStorage, MockQuerier> {
    mock_instance_with_options(
        wasm,
        MockInstanceOptions {
            available_capabilities: capabilities_from_csv(
                "iterator,cosmwasm_1_1,cosmwasm_1_2,cosmwasm_1_3,cosmwasm_1_4,cosmwasm_2_0,staking,stargate,babylon",
            ),
            gas_limit: 100_000_000_000_000,
            contract_balance: Some(funds),
            ..Default::default()
        },
    )
}

#[test]
fn instantiate_works() {
    // Setup
    let mut deps = mock_instance_on_babylon(WASM, &[]);
    let mock_api: MockApi = MockApi::default();
    let msg = InstantiateMsg {
        admin: mock_api.addr_make(CREATOR),
        bsn_id: "op-stack-l2-11155420".to_string(),
        min_pub_rand: 100,
    };
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg.clone());
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());

    // Check the config is properly stored in the state and returned
    let res: Config =
        from_json(query(&mut deps, mock_env(), QueryMsg::Config {}).unwrap()).unwrap();
    assert_eq!(msg.bsn_id, res.bsn_id);
    assert_eq!(msg.min_pub_rand, res.min_pub_rand);

    // Check the admin is properly stored in the state and returned
    let res: AdminResponse =
        from_json(query(&mut deps, mock_env(), QueryMsg::Admin {}).unwrap()).unwrap();
    assert_eq!(mock_api.addr_make(CREATOR), res.admin.unwrap());
}
