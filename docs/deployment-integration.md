# Deployment of thr Rollup BSN Contract

## Introduction

The Rollup BSN contract is a CosmWasm smart contract deployed on
the Babylon Genesis chain that tracks finality signatures for rollup blocks.
It verifies signatures, timestamps public randomness, detects equivocation, and
reports misbehavior for slashing. This is the core and only
contract that a rollup deploys to become a BSN. The contract must be deployed
on Babylon Genesis as it relies on direct interaction with it.

## Governance Notes

Depending on the Babylon Genesis network (e.g., testnet, mainnet) you
choose for the deployment of the rollup BSN, the network might be permissioned:
* **Permissioned CosmWasm**: Requires governane approval for deploying a smart
  contract. This can be granted in two ways:
  * `MsgStoreCode` proposal: Upload a contract code. Preferred for one-time deployments
  * `MsgUpdateParams` proposal: Add a Babylon Genesis address in an allow-list
    for which its members can permissionlessly upload code. This is typically
    used for contracts requiring periodic maintenance.
  > To learn more about permissioned CosmWasm,
  > see the [deployment
  > guide](https://docs.babylonlabs.io/guides/governance/submit_proposals/smart_contract_deployment/) 
  > and review past proposals in the [governance
  > forum](https://forum.babylon.foundation/c/gov-proposals/smart-contract-proposals/15).
* **Permissioned BSN Registration**: Requires a governance approval for
  the registration of a BSN. This can be granted via the submission of
  a governance proposal executing a `MsgRegisterConsumer` using the
  metadata defined in the [Rollup BSN Registration](#rollup-bsn-registration)
  section.
  <!-- TODO: add links to our forum section with guidelines -->

> **Note**: For networks that have both Permissioned CosmWasm and Permissioned
> BSN Registration two governance proposals will be required. A unified
> governance flow requiring only a single governance proposal is being
> examined.

For the rest of the document, we will assume a Permissionless CosmWasm and BSN
Registration network for simplicity. Listings that would require governance
will be highlighted appropriately.

## Instantiation

The Rollup BSN contract is instantiated as follows:
<!--- TODO: code listing with the instantiation.
The parameters can appear as constants, e.g., ADMIN -->

The parameters:
* `admin`: The Babylon Genesis address of the contract administrator.
* `bsn_id`: The unique identifier for the BSN rollup.
  Ensure that this is unique and not already used by another BSN on Babylon
  Genesis as this will affect your registration.
* `min_pub_rand`: Minimum public randomness values included per public
  randomness commit by finality providers.
* `rate_limiting_interval`: Length (in blocks) of the interval for
  rate-limiting submissions.
* `max_msgs_per_interval`: Maximum number of submissions allowed per finality
  provider within each interval.
* `fp_allowlist`: List of finality providers from which the contract will
  accept finality signatures and randomness.
* `submission_interval`: Interval restricting when finality providers can
  submit finality signatures.

<!-- TODO: once we have docs for the allow list and rate limiting, we can link
those here -->

## Rollup BSN Registration

After deploying and instantiating the Rollup BSN contract, the
rollup must register on Babylon Genesis. Registration requires 
submitting metadata to identify and describe the BSN

Required metadata for BSN registration:
* `consumer_id`: BSN ID of your rollup (same as the one you used on contract
  instantiation)
* `consumer_name`: Human-readable name of your rollup BSN (e.g., `"DeFi Rollup Chain"`)
* `consumer_description`: Brief description of the rollup BSN's purpose
* `max_multi_staked_fps`: Maximum number of rollup FPs per BTC delegation. Prevents delegators from splitting their BTC across too many networks (recommended: `3-5`)
<!-- TODO: this should not be here, we will have a global limit on fps -->
* `rollup_finality_contract_address`: Babylon Genesis address of the deployed Rollup BSN contract (`bbn1...` format)

To register the BSN, use:
```shell
babylond tx btcstkconsumer register-consumer \
                                <consumer_id> \
                                <consumer_name> \
                                <consumer_ description> \
                                <max_multi_staked_fps> \
                                <rollup_finality_contract_address>
```

> **Note**: The above operation requires governance in permissioned
> registration networks.

## Contract Maintenance

The Rollup BSN contract exposes `admin-only` functions for ongoing
contract management. These operations allow storage cleanup, role 
updates, and future configuration changes without redeployment.

<!-- TODO:
     1. Add code listings on how the operations are performed.
     2. Add text describing why someone would modify those.
        The document should provide understanding on how to be a
        contract admin, not just on what are the tech capabilities.
     3. We can also link to the documentations we have (e.g. `PRUNING.md`) -->

### Modifying the Contract Administrator

- `UpdateAdmin`: Transfers contract admin rights to a new Babylon address. Validates the address format and enforces 
access control using `cw_controllers::Admin`. Executed via `wasm execute` with the `UpdateAdmin` message

### Data Pruning

- `PruneData`: Removes all finality signatures and public randomness for rollup blocks with `height ≤ block_height`. 
Executed via `wasm execute` with the `PruneData` message. Optional parameters control 
batch size to prevent gas exhaustion


### Modifying the Finality Providers Allow-List
- `SetFPAllowlist`: Manages the FP allowlist by adding or removing FPs authorized to submit signatures and randomness

### Rate Limiting Submissions 
- `SetSubmissionInterval`: Updates the submission interval configuration to control how frequently each FP can 
submit signatures (e.g., every X-th block)

<!-- TODO: what about public randomness parameters? -->

## External Integration

The Rollup BSN contract is used by two main types of off-chain actors:

<!--TODO: we don't need to be technical here, just a high-level paragraph of
each with links to the relevant repos/docs is enough -->
- **Finality Providers** submit data to the contract:
  - `CommitPublicRandomness`: Commits a Merkle root of public
 randomness, which must be BTC-timestamped on Babylon before use
  - `SubmitFinalitySignature`: Submits an EOTS signature for a 
  rollup block, including Merkle proof linking to prior randomness

- **Finality Gadgets** and other off-chain services query the 
contract:
  - `BlockVoters`: Lists FPs that signed a given block
  - `Config`: Returns BSN configuration (ID, rate limits, min 
  randomness).
  - `FirstPubRandCommit` / `LastPubRandCommit`: Retrieves commitment 
  ranges for a given FP.
  - `ListPubRandCommit`: Paginates randomness commitments for 
  coordination with BTC timestamping
