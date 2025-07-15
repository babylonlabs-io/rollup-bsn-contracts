# Rollup BSN Contract Guide

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
