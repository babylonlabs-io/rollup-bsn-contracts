# Rollup BSN Contract: Deployment & Integration

## Introduction

The Rollup BSN contract is a CosmWasm smart contract deployed on the Babylon Genesis
chain that tracks finality signatures for rollup blocks. It verifies who signed,
detects double-signing, and reports misbehavior for slashing. This is the core and only
contract that a rollup needs to deploy to become a BSN. The contract must be deployed
on Babylon Genesis because it relies on Babylon-specific modules and state.


## Instantiation Parameters

Parameters required to configure the Rollup BSN contract upon deployment ([reference](../contracts/finality/src/msg.rs#L12-L19)):

- `admin`: Babylon address of the contract administrator
- `bsn_id`: Unique identifier for the BSN rollup
- `min_pub_rand`: Minimum required public randomness submissions from Finality Providers (FPs)
- `rate_limiting_interval`: Length (in blocks) of the interval for rate-limiting submissions
- `max_msgs_per_interval`: Maximum number of submissions allowed per FP within each interval

The following parameters are planned but not yet implemented:
- `fp_allowlist`: List of allowed FPs; contract only accepts randomness and finality signatures from allowlisted FPs ([issue](https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/72))
- `submission_interval`: Interval (every Y-th block) restricting when FPs can submit finality signatures ([issue](https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/78))

## Rollup BSN Registration
After deploying and instantiating the Rollup BSN contract, the
rollup must register on Babylon Genesis. Registration requires 
submitting metadata to identify and describe the BSN

Required metadata for BSN registration:
- `consumer_id`: Chain ID of your rollup (e.g., `"bsn-rollup-mainnet"`)
- `consumer_name`: Human-readable rollup name (e.g., `"DeFi Rollup Chain"`)
- `consumer_description`: Brief description of the rollup's purpose
- `max_multi_staked_fps`: Maximum number of rollup FPs per BTC delegation. Prevents delegators from splitting their BTC across too many networks (recommended: `3-5`)
- `rollup_finality_contract_address`: Babylon Genesis address of the deployed Rollup BSN contract (`bbn1...` format)

To register the BSN, use:
```bash
babylond tx btcstkconsumer register-consumer <consumer_id> <name> <description> <max_multi_staked_fps> <rollup_finality_contract_address> [flags]
```

## Governance Notes
Babylon devnet and testnet are permissionless — contracts can be deployed and BSNs registered without restrictions.

Babylon Genesis mainnet is permissioned. Two governance steps are
required:

- **Contract deployment**:  Submit one of the following:
   - `MsgStoreCode`: Upload your contract code via proposal. Preferred for one-time deployments.
  - `MsgUpdateParams`: Whitelist your Babylon address under ` code_upload_access`. Useful for frequent deployers.

  To learn more, see the [deployment guide](https://docs.babylonlabs.io/guides/governance/submit_proposals/smart_contract_deployment/)  
  and review past proposals in the [governance forum](https://forum.babylon.foundation/c/gov-proposals/smart-contract-proposals/15)

- **BSN registration**:  Submit a `MsgRegisterConsumer` proposal 
using the metadata defined in the [Rollup BSN Registration]
(#rollup-bsn-registration) section.
 
 > Note: A unified governance flow combining either `MsgStoreCode`
or `MsgUpdateParams` with `MsgRegisterConsumer` is under 
consideration to simplify BSN onboarding on mainnet

## Contract Maintenance

The Rollup BSN contract exposes `admin-only` functions for ongoing
contract management. These operations allow storage cleanup, role 
updates, and future configuration changes without redeployment

Available operations:
- `PruneData`: Removes all finality signatures and public randomness for rollup blocks with `height ≤ block_height`. Executed via `wasm 
execute` with the `PruneData` message. Optional parameters control 
batch size to prevent gas exhaustion

- `UpdateAdmin`: Transfers contract admin rights to a new Babylon address. Validates the address format and enforces access control using `cw_controllers::Admin`. Executed via `wasm execute` with the `UpdateAdmin` message

The following operations are planned but not yet implemented:

- `SetFPAllowlist`: Manages the FP allowlist by adding or removing FPs authorized to submit signatures and randomness

- `SetSubmissionInterval`: Updates the submission interval configuration to control how frequently each FP can submit signatures (e.g., every X-th block)

## External Integration

The Rollup BSN contract is used by two main types of off-chain actors:

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


