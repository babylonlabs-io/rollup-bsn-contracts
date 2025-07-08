use anybuf::{Anybuf, Bufany};
use babylon_bindings::BabylonQuery;
use cosmwasm_std::{Binary, Deps, StdResult};

/// FinalityProviderResponse defines a finality provider with voting power information.
/// NOTE: this is a subset of the response from Babylon, we only need the slashed heights
pub struct FinalityProviderResponse {
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    pub slashed_btc_height: u64,
    // bsn_id is the ID of the BSN the finality provider is securing
    pub bsn_id: String,
}

pub fn query_finality_provider(
    deps: Deps<BabylonQuery>,
    fp_btc_pk_hex: String,
) -> StdResult<FinalityProviderResponse> {
    let query_data = Anybuf::new()
        .append_string(1, fp_btc_pk_hex.clone())
        .into_vec();

    let res_data: Binary = deps.querier.query_grpc(
        "/babylon.btcstaking.v1.Query/FinalityProvider".to_string(),
        Binary::new(query_data),
    )?;

    let res_decoded = Bufany::deserialize(&res_data).unwrap();
    // see https://github.com/babylonlabs-io/babylon/blob/main/proto/babylon/btcstaking/v1/query.proto
    // for protobuf definition
    let res_fp = res_decoded.message(1).unwrap();
    let res: FinalityProviderResponse = FinalityProviderResponse {
        slashed_babylon_height: res_fp.uint64(6).unwrap(),
        slashed_btc_height: res_fp.uint64(7).unwrap(),
        bsn_id: res_fp.string(12).unwrap(),
    };

    Ok(res)
}

impl FinalityProviderResponse {
    /// Checks if this finality provider has been slashed based on the response from Babylon
    pub fn is_slashed(&self) -> bool {
        self.slashed_babylon_height != 0 || self.slashed_btc_height != 0
    }
}
