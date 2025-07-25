# Rollup BSN Finality Contract Management

## Table of Contents

1. [Introduction](#1-introduction)  
2. [BSN Lifecycle](#2-bsn-lifecycle)  
3. [Governance Notes](#3-governance-notes)  
4. [Configuration](#4-configuration)  
   4.1. [Parameter Selection Guidelines](#41-parameter-selection-guidelines)  
   4.2. [How Configuration is Set](#42-how-configuration-is-set)  
       4.2.1. [Instantiation](#421-instantiation)  
       4.2.2. [Updating Configuration](#422-updating-configuration)   
5. [Rollup BSN Registration](#5-rollup-bsn-registration)  
6. [Contract Maintenance](#6-contract-maintenance)  
   6.1. [Modifying the Contract Administrator](#61-modifying-the-contract-administrator)  
   6.2. [Modifying the Finality Providers Allow-List](#62-modifying-the-finality-providers-allow-list)  
   6.3. [Data Pruning](#63-data-pruning)  
7. [Querying Contract Data](#7-querying-contract-data)  
   7.1. [Querying Finality Votes](#71-querying-finality-votes)  
   7.2. [Querying Public Randomness](#72-querying-public-randomness)  
   7.3. [Querying Admin and Configuration](#73-querying-admin-and-configuration)  

## 1. Introduction

The Rollup BSN contract is a CosmWasm smart contract deployed on
the Babylon Genesis chain that tracks finality signatures for rollup blocks.
It verifies signatures, timestamps public randomness, detects equivocation, and
reports misbehavior for slashing. This is the core and only
contract that a rollup deploys to become a BSN.

## 2. BSN Lifecycle

<img width="3100" height="772" alt="governance" src="./assets/lifecycle.png" />

The following steps outline the full lifecycle of a Rollup BSN contract, from 
deployment to ongoing operation and management:

1. **Contract Code Upload**: Upload the compiled WASM bytecode to Babylon 
Genesis to obtain a code ID
2. **Contract Instantiation**: Create a contract instance using the code ID 
with your specific BSN configuration 
3. **BSN Registration**: Register your BSN with Babylon using the contract 
address. Once registered you become a valid BSN and finality providers can 
start joining to secure your BSN
4. **Contract Maintainance**: Manage the contract, query its state, and allow 
finality providers to submit signatures and randomness

## 3. Governance Notes

<img width="3100" height="772" alt="governance" src="./assets/governance.png" />

Depending on the Babylon Genesis network (e.g., testnet, mainnet) you
choose for the deployment of the rollup BSN, the network might be permissioned:
* **Permissioned CosmWasm**: Requires governance approval for deploying a smart
  contract. This can be granted in two ways:
  * `MsgStoreCode` proposal: Upload a contract code. Preferred for one-time 
deployments
  * `MsgAddCodeUploadParamsAddresses` proposal: Add a Babylon Genesis address 
in an allow-list
    for which its members can permissionlessly upload code. This is typically
    used for contracts requiring periodic maintenance.
    
  > To learn more about permissioned CosmWasm,
  > see the [deployment guide](https://docs.babylonlabs.io/guides/governance/submit_proposals/smart_contract_deployment/) 
  > and review past proposals in the [Babylon Foundation forum](https://forum.babylon.foundation/c/gov-proposals/smart-contract-proposals/15).

* **Permissioned BSN Registration**: Requires a governance approval for
  the registration of a BSN. This can be granted via the submission of
  a governance proposal executing a `MsgRegisterConsumer` using the
  metadata defined in the [Rollup BSN Registration](#rollup-bsn-registration)
  section.

<!-- TODO: once we write the governance guidlines for BSN link it here -->

> **Note**: If a network uses both Permissioned CosmWasm and 
> Permissioned BSN Registration, two separate governance proposals 
> are currently required. A unified
> governance flow requiring only a single governance proposal is being
> examined.

For the rest of the document, we will assume a Permissionless CosmWasm and BSN
Registration network for simplicity. Listings that would require governance
will be highlighted appropriately.

## 4. Contract Parameters

The Rollup BSN contract is governed by several types of parameters that control
its behavior, security, and operational limits. These parameters are organized
into three main categories:

### 4.1 Parameter Structures

**Core Configuration**

The main configuration is stored in the contract state and contains operational parameters:

```rust
pub struct Config {
    /// Unique identifier for the BSN (Bitcoin Supercharged Network) that this
    /// contract secures
    pub bsn_id: String,
    /// Minimum number of public randomness values required in commitments
    pub min_pub_rand: u64,
    /// Rate limiting configuration to prevent spam
    pub rate_limiting: RateLimitingConfig,
    /// Rollup block height at which the BSN system is activated (0 = immediate
    /// activation). Only affects `SubmitFinalitySignature` messages.
    pub bsn_activation_height: u64,
    /// Interval between allowed finality signature submissions. Signatures can
    /// only be submitted at rollup block heights where `(height -
    /// bsn_activation_height) % interval == 0`.
    pub finality_signature_interval: u64,
}

pub struct RateLimitingConfig {
    /// Maximum number of messages allowed from each FP per interval
    pub max_msgs_per_interval: u32,
    /// Number of Babylon blocks in each interval
    pub block_interval: u64,
}
```

**Administrative Parameters**

```rust
/// Contract administrator stored separately using cw-controllers
pub admin: Admin  // Stored as a Babylon Genesis address (String)
```

**Finality Provider Allow-list**

```rust
/// Map of allowed finality provider BTC public keys (as bytes) to a unit value
/// Only populated if allowlist feature is enabled at instantiation
pub allowed_finality_providers: Map<&[u8], ()>
```

> **Note**: These parameters are set during contract instantiation using the `InstantiateMsg` 
> structure. The instantiation message combines all these parameters into a single structure,
> as shown in the [Instantiation](#421-instantiation) section below.
> Some of the parameters can be further modified as part of
> [Contract Maintenance](#6-contract-maintenance).

### 4.2 Parameter Selection Guidelines

**admin**  
> **Type**: String  
> **Required**: Yes  
> **Mutable**: Yes (via `update_admin` message)

The `admin` is a Bech32 Babylon Genesis address that has administrative control over the contract.
This address is authorized to perform privileged actions such as modifying the allow-list,
pruning data, or executing other administrative operations.
It is critical for this key to be secured.

> **Note**: The admin can also be a governance address.
> While this helps with decentralization, reaction in
> emergency situations might be slower.

**bsn_id**  
> **Type**: String (unique)  
> **Required**: Yes  
> **Mutable**: No  


The unique identifier of the BSN on Babylon Genesis. It must match the one
used during the Babylon Genesis BSN registration.
The identifier can only contain alphanumeric characters, hyphens, and
underscores with a maximum length of 100 characters.

**min_pub_rand**  
> **Type**: Integer (positive)  
> **Required**: Yes  
> **Mutable**: No  

The `min_pub_rand` parameter sets the minimum number of public randomness values that
finality providers must include in each public randomness commitment.

**rate_limiting_interval**  
> **Type**: Integer (positive)  
> **Required**: Yes  
> **Mutable**: No  

The `rate_limiting_interval` specifies the length (in Babylon Genesis blocks) of the rate limiting window.
Within each interval, a finality provider can submit a limited number of messages,
including both public randomness commitments and finality signature submissions.
Once the interval resets, the provider's submission count is cleared.
This value is utilized to prevent spam or accidental flooding by controlling
how often a provider can interact with the contract.

**max_msgs_per_interval**  
> **Type**: Integer (positive)  
> **Required**: Yes  
> **Mutable**: No  

The `max_msgs_per_interval` sets the maximum number of messages a finality provider
can submit during each rate limiting interval.
If a finality provider reaches this limit,
any further messages in the current interval will be rejected.
This parameter, together with `rate_limiting_interval`,
enforces the submission rate for all message types.

**bsn_activation_height**  
> **Type**: Integer (positive)  
> **Required**: Yes  
> **Mutable**: No  

The `bsn_activation_height` refers to the first block of
the rollup BSN that's expected to receive finality signatures.
This parameter is used together with the `finality_signature_interval`
to determine the block heights that should be voted for by finality providers.

**finality_signature_interval**  
> **Type**: Integer (positive)  
> **Required**: Yes  
> **Mutable**: No  

The `finality_signature_interval` defines the epoch size (in rollup blocks)
in which finality providers submit signatures for blocks.
Signatures are only accepted every N blocks after activation,
where `(height - bsn_activation_height) % finality_signature_interval == 0`.
Higher intervals reduce computational overhead but provide less frequent
finality confirmations.
The interval should not be more frequent than the Babylon Genesis block time.

**allowed_finality_providers**  
> **Type**: Array[String] (Hex-encoded compressed BTC public keys)  
> **Required**: No (default [])  
> **Mutable**: Yes (via `add_to_allowlist` and `remove_from_allowlist` messages) 

The `allowed_finality_providers` is a list of BTC public keys that are authorized
to submit finality signatures and public randomness to the contract.
Each entry in the list must be a hex-encoded compressed BTC public key.
Messages from unauthorized keys will be rejected by the contract.
This parameter defines the initial allow-list at deployment time.
It can be modified after instantiation by the contract admin.

### 4.2. Setting Parameters

#### 4.2.1. Instantiation

<img width="3033" height="275" alt="instantiate" src="./assets/instantiate.png" />

The contract parameters described in section 4.1 are initialized when the contract is instantiated. 
The instantiation message combines all parameters into a single `InstantiateMsg` structure:

```rust
pub struct InstantiateMsg {
    /// Initial admin address for the contract who can update settings
    pub admin: String,
    /// Unique identifier for the BSN this contract secures
    pub bsn_id: String,
    /// Minimum number of public randomness values required in commitments
    pub min_pub_rand: u64,
    /// Number of Babylon blocks in each interval
    pub rate_limiting_interval: u64,
    /// Maximum messages allowed per finality provider per interval
    pub max_msgs_per_interval: u32,
    /// Rollup block height at which the BSN system is activated
    pub bsn_activation_height: u64,
    /// Interval between allowed finality signature submissions
    pub finality_signature_interval: u64,
    /// Optional list of BTC public keys (hex) to pre-populate the allowlist
    pub allowed_finality_providers: Option<Vec<String>>,
}
```

Use the following command to deploy and configure the contract:

```shell
# Note: Use "$VAR" for strings, $VAR for numbers

INSTANT_MSG=$(cat <<EOF
{
  "admin": "$ADMIN_ADDRESS",
  "bsn_id": "$BSN_ID",
  "bsn_activation_height": $BSN_ACTIVATION_HEIGHT,
  "finality_signature_interval": $FINALITY_SIGNATURE_INTERVAL,
  "max_msgs_per_interval": $MAX_MSGS_PER_INTERVAL,
  "min_pub_rand": $MIN_PUB_RAND,
  "rate_limiting_interval": $RATE_LIMITING_INTERVAL,
  "allowed_finality_providers": ["$FP_PUBKEY_1", "$FP_PUBKEY_2"]
}
EOF
)

babylond tx wasm instantiate $CODE_ID '$INSTANT_MSG'
```
> **Note**: $CODE_ID refers to the uploaded contract code identifier on Babylon Genesis

#### 4.2.2. Updating Parameters

After instantiation, only certain configuration parameters can be updated. These updates are performed by 
sending execute messages to the contract.
Each operation is executed with:

```shell
babylond tx wasm execute <CONTRACT_ADDRESS> '<JSON_MSG>'
```
> **Note**: `<CONTRACT_ADDRESS>` refers to the address of the deployed
> Rollup BSN contract on Babylon.
> `<JSON_MSG>` is the execute message in JSON format, described below.

**Update Admin**

```shell
JSON_MSG={
  "update_admin": {
    "admin": "$NEW_ADMIN_ADDRESS"
  }
}
```
> **Variable:**  
> `$NEW_ADMIN_ADDRESS`: The new admin's Bech32 Babylon Genesis address (e.g., `bbn1...`)

**Add to Allow-List**

```shell
JSON_MSG={
  "add_to_allowlist": {
    "fp_pubkey_hex_list": [
      "$FP_BTC_PUBKEY"
    ]
  }
}
```
> **Variable:**  
> `$FP_BTC_PUBKEY`: Hex-encoded compressed BTC public key of the Finality Provider

**Remove from Allow-List**

```shell
JSON_MSG={
  "remove_from_allowlist": {
    "fp_pubkey_hex_list": [
      "$FP_BTC_PUBKEY"
    ]
  }
}
```
> **Variable:**  
> `$FP_BTC_PUBKEY`: Hex-encoded compressed BTC public key of the Finality Provider

For details on when and why to use these messages, see [Contract Maintenance](#6-contract-maintenance).

## 5. Rollup BSN Registration

<img width="3032" height="287" alt="register" src="./assets/register.png" />

After deploying and instantiating the Rollup BSN contract, the
rollup must register on Babylon Genesis. Registration as a BSN requires 
submitting metadata to identify and describe the BSN

To register the BSN, use:
```shell
babylond tx btcstkconsumer register-consumer \
  "$CONSUMER_ID" \
  "$CONSUMER_NAME" \
  "$CONSUMER_DESCRIPTION" \
  "$ROLLUP_FINALITY_CONTRACT_ADDRESS"
```

Required metadata for BSN registration:
* `consumer_id`: BSN ID of your rollup (same as the BSN ID you used on contract
  instantiation)
* `consumer_name`: Human-readable name of your rollup BSN (e.g., `"DeFi Rollup 
Chain"`)
* `consumer_description`: Brief description of the rollup BSN's purpose
* `rollup_finality_contract_address`: Babylon Genesis address of the deployed 
Rollup BSN contract (`bbn1...` format)

> **Governance Note**: The above operation can only be executed by governance
> in permissioned registration networks.

## 6. Contract Maintenance

<img width="1848" height="677" alt="adminRole" 
src="./assets/adminFunctions.png" />

The Rollup BSN contract exposes `admin-only` functions for ongoing management. 
These allow you to clean up
old data, update roles, and adjust configuration without redeploying the 
contract.

### 6.1. Modifying the Contract Administrator

Transferring contract admin rights to a new Babylon Genesis address
is typically used when rotating keys, migrating ownership to another entity,
or responding to a security incident. Only the current admin can perform this operation. 

See [Updating Configuration](#422-updating-configuration) for the message format.

### 6.2. Modifying the Finality Providers Allow-List

The allow-list controls which Finality Providers (FPs) are authorized
to submit signatures and public randomness.
Use the add/remove allow-list messages to onboard new FPs, rotate keys, or revoke access
from inactive or misbehaving providers. All changes are on-chain and transparent.

See [Updating Configuration](#422-updating-configuration) for the message formats.

### 6.3. Data Pruning

Data pruning removes all finality signatures and public randomness for rollup blocks
with height less than or equal to a specified value.
This is useful for reducing on-chain storage as the chain grows.
Optional fields control pruning batch size to avoid gas exhaustion.

```shell
MSG={
  "prune_data": {
    "rollup_height": $BLOCK_HEIGHT,
    "max_signatures_to_prune": $MAX_SIGS,
    "max_pub_rand_values_to_prune": $MAX_PUB_RAND
  }
}

babylond tx wasm execute <CONTRACT_ADDRESS> '$MSG'
```

> **Variables:**  
> `$BLOCK_HEIGHT`: Rollup block height threshold for pruning (integer)  
> `$MAX_SIGS`: Maximum number of signatures to prune in this operation (integer)  
> `$MAX_PUB_RAND`: Maximum number of public randomness values to prune in this operation (integer)

See [PRUNING.md](./PRUNING.md) for detailed guidelines on selecting safe pruning heights and best practices.

## 7. Querying Contract Data

The Rollup BSN contract exposes queries to obtain information about finality 
signatures 
submitted by Finality Providers and their public randomness commitments. 
Queries are 
executed using the following command format:
```shell
babylond query wasm contract-state smart <CONTRACT_ADDRESS> '<QUERY_MSG>' \
  --node $NODE_RPC \
  --output json
```
Note: `CONTRACT_ADDRESS` refers to the address of the deployed Rollup BSN 
contract on Babylon. `QUERY_MSG` 
is the execute message in JSON format, described in the sections below

### 7.1. Querying Finality Votes

To identify Finality Providers who submitted signatures for a specific rollup 
block, 
query by block height and hash:
```shell
QUERY_MSG={
  "block_voters": {
    "height": $BLOCK_HEIGHT,
    "hash_hex": "$BLOCK_HASH_HEX"
  }
}
```
> **Variables:**  
> `$BLOCK_HEIGHT`: Rollup block height to query (integer)  
> `$BLOCK_HASH_HEX`: Hex-encoded block hash (string)  

### 7.2. Querying Public Randomness

The contract provides multiple ways to fetch public randomness commitments from 
Finality Providers. 
To return the **first commitment** posted by a provider:
```shell
QUERY_MSG={
  "first_pub_rand_commit": {
    "btc_pk_hex": "$FP_BTC_PUBKEY"
  }
}
```
> **Variables:**  
> `$FP_BTC_PUBKEY`: Hex-encoded compressed BTC public key of the Finality Provider (string)  

To return the **most recent commitment**:
```shell
QUERY_MSG={
  "last_pub_rand_commit": {
    "btc_pk_hex": "$FP_BTC_PUBKEY"
  }
}
```
> **Variables:**  
> `$FP_BTC_PUBKEY`: Hex-encoded compressed BTC public key of the Finality Provider (string)  

To page through a provider’s **full history of commitments**:
```shell
QUERY_MSG={
  "list_pub_rand_commit": {
    "btc_pk_hex": "$FP_BTC_PUBKEY",
    "start_after": $START_HEIGHT, 
    "limit": $LIMIT,              
    "reverse": $REVERSE_ORDER     
  }
}
```
> **Variables:**  
> `$FP_BTC_PUBKEY`: Hex-encoded compressed BTC public key of the Finality Provider (string)  
> `$START_HEIGHT`: (Optional) Only return commitments after this rollup block height (integer)  
> `$LIMIT`: (Optional) Maximum number of commitments to return (integer, default: 10, max: 30)  
> `$REVERSE_ORDER`: (Optional) Return results in reverse order (boolean, default: false)  

### 7.3. Querying Admin and Configuration

The contract also exposes queries for inspecting the current configuration and 
state
To return the **current admin address**:
```shell
QUERY_MSG={
  "admin": {}
}
```
To return the **contract configuration**, including the BSN ID, rate limits, 
and other parameters:
```shell
QUERY_MSG={
  "config": {}
}
```
To return the list of **allow-listed Finality Providers** (BTC public keys in 
hex format):
```shell
QUERY_MSG={
  "allowed_finality_providers": {}
}
```
