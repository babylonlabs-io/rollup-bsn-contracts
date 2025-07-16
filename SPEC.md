# Finality contract specification for the rollup integration

- [1. Abstract](#1-abstract)
- [2. Background](#2-background)
  - [2.1. BTC staking integration](#21-btc-staking-integration)
  - [2.2. The role of the finality contract](#22-the-role-of-the-finality-contract)
- [3. Keywords](#3-keywords)
- [4. Specification](#4-specification)
  - [4.1. Babylon Genesis chain message interfaces](#41-babylon-genesis-chain-message-interfaces)
    - [4.1.1. Message: EquivocationEvidence (MUST)](#411-message-equivocationevidence-must)
  - [4.2. Babylon Genesis chain gRPC queries](#42-babylon-genesis-chain-grpc-queries)
    - [4.2.1. QueryFinalityProvider (MUST)](#421-queryfinalityprovider-must)
  - [4.3. Babylon Genesis chain Custom Queries](#43-babylon-genesis-chain-custom-queries)
    - [4.3.1. CurrentEpoch (MUST)](#431-currentepoch-must)
    - [4.3.2. LastFinalizedEpoch (MUST)](#432-lastfinalizedepoch-must)
  - [4.4. Contract Instantiation](#44-contract-instantiation)
  - [4.5. Signing Context](#45-signing-context)
  - [4.6. Rate Limiting (MUST)](#46-rate-limiting-must)
  - [4.7. Finality Contract message handlers](#47-finality-contract-message-handlers)
    - [4.7.1. CommitPublicRandomness (MUST)](#471-commitpublicrandomness-must)
    - [4.7.2. SubmitFinalitySignature (MUST)](#472-submitfinalitysignature-must)
    - [4.7.3. UpdateAdmin (SHOULD)](#473-updateadmin-should)
    - [4.7.4. PruneData (SHOULD)](#474-prunedata-should)
  - [4.8. Contract State Storage](#48-contract-state-storage)
    - [4.8.1. Core Configuration](#481-core-configuration)
    - [4.8.2. Rate Limiting Storage](#482-rate-limiting-storage)
    - [4.8.3. Finality State Storage](#483-finality-state-storage)
    - [4.8.4. Public Randomness Storage](#484-public-randomness-storage)
  - [4.9. Finality contract queries](#49-finality-contract-queries)
    - [4.9.1. BlockVoters (MUST)](#491-blockvoters-must)
    - [4.9.2. FirstPubRandCommit (MUST)](#492-firstpubrandcommit-must)
    - [4.9.3. LastPubRandCommit (MUST)](#493-lastpubrandcommit-must)
    - [4.9.4. ListPubRandCommit (MUST)](#494-listpubrandcommit-must)
    - [4.9.5. Admin (SHOULD)](#495-admin-should)
    - [4.9.6. Config (SHOULD)](#496-config-should)
    - [4.9.7. AllowedFinalityProviders (SHOULD)](#497-allowedfinalityproviders-should)
- [5. Implementation status](#5-implementation-status)
  - [5.1. Babylon implementation status](#51-babylon-implementation-status)
  - [5.2. Finality contract implementation status](#52-finality-contract-implementation-status)

## 1. Abstract

This document specifies the design and requirements of the finality contract
used in integrating rollups with Babylon's Bitcoin staking protocol. The
finality contract enables BSNs to inherit Bitcoin-backed economic security by
recording finality signatures from BSN finality providers, enforcing slashing
for equivocation, and exposing finality signatures to the integrated BSN. The
document details the contract's interfaces, message handlers, and queries, and
provides guidance for implementers seeking to leverage Babylon's Bitcoin
security for rollup finality.

## 2. Background

### 2.1. BTC staking integration

Babylon's phase-3 network introduces Bitcoin staking integration to provide
Bitcoin security to other decentralized systems, known as Bitcoin Supercharged
Networks (BSNs), such as L1 blockchains and rollups. This integration enables
BTC stakers to delegate their native BTC to finality providers on BSNs, and each
BSN will leverage this BTC stake for economic security. For more details, see
the [Cosmos integration
1-pager](https://www.notion.so/BTC-staking-integration-for-Cosmos-chains-1-pager-f0574cd4e624475eb00d64912698a38c?pvs=4)
and [OP Stack integration
1-pager](https://www.notion.so/BTC-staking-integration-for-OP-stack-chains-1-pager-16f28a013c55805fbebdec6102b43c92?pvs=4).

### 2.2. The role of the finality contract

The finality contract is a necessary component in the integration architecture
between rollups and Babylon's Bitcoin staking protocol. This contract is
responsible for two primary functions:

1. Maintaining finality signatures submitted by rollup BSN finality providers,
   and
2. Enforcing slashing upon detection of equivocation by BSN finality providers.

To determine Bitcoin staking finalization status, each rollup full node
maintains a connection to a Babylon Genesis full node to retrieve finality
signatures. Please refer to the [OP stack integration
1-pager](https://www.notion.so/BTC-staking-integration-for-OP-stack-chains-1-pager-16f28a013c55805fbebdec6102b43c92?pvs=4)
as an example in the context of integrating an OP stack rollup.

## 3. Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC
2119](https://www.ietf.org/rfc/rfc2119.html) and [RFC
8174](https://www.ietf.org/rfc/rfc8174.html).

## 4. Specification

This section outlines the detailed requirements for implementing a finality
contract that integrates with Babylon's Bitcoin staking protocol. It covers the
interfaces with Babylon Genesis chain, message handlers, and queries that all
finality contract implementations must or should support. The specification
distinguishes between required ("MUST") and recommended ("SHOULD") components.

### 4.1. Babylon Genesis chain message interfaces

This section outlines the interfaces that Babylon Genesis chain has to implement
and the finality contract needs to interact with.

#### 4.1.1. Message: EquivocationEvidence (MUST)

The Babylon Genesis chain MUST provide a message interface for finality
contracts to report equivocation evidence when finality providers double-sign:

```rust
// Interface provided by Babylon Genesis chain
BabylonMsg::MsgEquivocationEvidence {
    /// Address of the entity reporting the equivocation
    signer: String,
    /// BTC public key of the equivocating finality provider (hex-encoded)
    fp_btc_pk_hex: String,
    /// Block height at which an equivocation occurred
    block_height: u64,
    /// Public randomness value used in both signatures (hex-encoded)
    pub_rand_hex: String,
    /// Application hash of the canonical block (hex-encoded)
    canonical_app_hash_hex: String,
    /// Application hash of the fork block (hex-encoded)
    fork_app_hash_hex: String,
    /// EOTS signature on the canonical block (hex-encoded)
    canonical_finality_sig_hex: String,
    /// EOTS signature on the fork block (hex-encoded)
    fork_finality_sig_hex: String,
    /// Signing context used for the signatures
    signing_context: String,
}
```

**Expected behaviour of Babylon Genesis chain:** Upon receiving the message, the
Babylon chain MUST validate the evidence cryptographically, extract the finality
provider's secret key using EOTS, remove them from the active set, set their
voting power to zero, and record the evidence.

**Usage Context:** Finality contracts MUST send this when detecting
double-signing by a finality provider at the same height.

### 4.2. Babylon Genesis chain gRPC queries

The Babylon Genesis chain MUST provide the contracts with access to the
following gRPC endpoints through the whitelist configuration in the [Babylon
chain](https://github.com/babylonlabs-io/babylon/blob/b9774782f38e9758c4f5aafab1e1e45dde0f3838/wasmbinding/grpc_whitelist.go).
<!-- TODO: use a release rather than a commit for the pointer -->

```go
func WhitelistedGrpcQuery() wasmkeeper.AcceptedQueries {
    return wasmkeeper.AcceptedQueries{
        // btcstkconsumer
        "/babylon.btcstaking.v1.Query/FinalityProvider": func() proto.Message {
            return &btcstakingtypes.QueryFinalityProviderResponse{}
        },
        // btcstaking
        "/babylon.btcstaking.v1.Query/FinalityProviderCurrentPower": func() proto.Message {
            return &ftypes.QueryFinalityProviderCurrentPowerResponse{}
        },
        // for testing
        "/babylon.epoching.v1.Query/CurrentEpoch": func() proto.Message {
            return &epochtypes.QueryCurrentEpochResponse{}
        },
    }
}
```

#### 4.2.1. QueryFinalityProvider (MUST)

Query `/babylon.btcstaking.v1.Query/FinalityProvider` returns the finality
provider information for the finality provider BTC PK. This query is used for
verifying that the finality provider exists, is not slashed, and is associated
with the correct BSN.

```protobuf
// QueryFinalityProviderRequest requests information about a finality provider
message QueryFinalityProviderRequest {
  // fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality
  // provider
  string fp_btc_pk_hex = 1;
}

// QueryFinalityProviderResponse contains information about a finality provider
message QueryFinalityProviderResponse {
  // finality_provider contains the FinalityProvider
  FinalityProviderResponse finality_provider = 1;
}

// FinalityProviderResponse defines a finality provider with voting power
// information.
message FinalityProviderResponse {
  // description defines the description terms for the finality provider.
  cosmos.staking.v1beta1.Description description = 1;
  // commission defines the commission rate of the finality provider.
  string commission = 2 [
    (cosmos_proto.scalar) = "cosmos.Dec",
    (gogoproto.customtype) = "cosmossdk.io/math.LegacyDec"
  ];
  // addr is the address to receive commission from delegations.
  string addr = 3 [ (cosmos_proto.scalar) = "cosmos.AddressString" ];
  // btc_pk is the Bitcoin secp256k1 PK of this finality provider
  // the PK follows encoding in BIP-340 spec
  bytes btc_pk = 4
      [ (gogoproto.customtype) =
            "github.com/babylonlabs-io/babylon/v3/types.BIP340PubKey" ];
  // pop is the proof of possession of the BTC_PK by the fp addr.
  // Essentially is the signature where the BTC SK sigs the fp addr.
  ProofOfPossessionBTC pop = 5;
  // slashed_babylon_height indicates the Babylon height when
  // the finality provider is slashed.
  // if it's 0 then the finality provider is not slashed
  uint64 slashed_babylon_height = 6;
  // slashed_btc_height indicates the BTC height when
  // the finality provider is slashed.
  // if it's 0 then the finality provider is not slashed
  uint32 slashed_btc_height = 7;
  // height is the queried Babylon height
  uint64 height = 8;
  // jailed defines whether the finality provider is jailed
  bool jailed = 9;
  // highest_voted_height is the highest height for which the
  // finality provider has voted
  uint32 highest_voted_height = 10;
  // commission_info contains information details of the finality provider
  // commission.
  CommissionInfo commission_info = 11;
  // bsn_id is the ID of the BSN the finality provider is securing
  string bsn_id = 12;
}

// Description defines a validator description.
message Description {
  // moniker defines a human-readable name for the validator.
  string moniker = 1;
  // identity defines an optional identity signature (ex. UPort or Keybase).
  string identity = 2;
  // website defines an optional website link.
  string website = 3;
  // security_contact defines an optional email for security contact.
  string security_contact = 4;
  // details define other optional details.
  string details = 5;
}

// ProofOfPossessionBTC is the proof of possession that a Babylon
// address and a Bitcoin secp256k1 secret key are held by the same
// person
message ProofOfPossessionBTC {
    // btc_sig_type indicates the type of btc_sig in the pop
    BTCSigType btc_sig_type = 1;
    // btc_sig is the signature generated via sign(sk_btc, babylon_staker_address)
    // the signature follows encoding in either BIP-340 spec or BIP-322 spec
    bytes btc_sig = 2;
}

// BTCSigType indicates the type of btc_sig in a pop
enum BTCSigType {
    // BIP340 means the btc_sig will follow the BIP-340 encoding
    BIP340 = 0;
    // BIP322 means the btc_sig will follow the BIP-322 encoding
    BIP322 = 1;
    // ECDSA means the btc_sig will follow the ECDSA encoding
    // ref: https://github.com/okx/js-wallet-sdk/blob/a57c2acbe6ce917c0aa4e951d96c4e562ad58444/packages/coin-bitcoin/src/BtcWallet.ts#L331
    ECDSA = 2;
}
```

### 4.3. Babylon Genesis chain Custom Queries

Finality contracts MUST utilize custom queries provided by the
[babylon-bindings](https://github.com/babylonlabs-io/bindings/) crate to
interact with Babylon-specific functionality. These custom queries provide
access to Babylon chain state that is not available through standard CosmWasm
queries.

**Required Dependencies:** The contract must include the `babylon_bindings`
crate which provides CosmWasm bindings to custom
[Babylon](https://github.com/babylonlabs-io/babylon) features.

#### 4.3.1. CurrentEpoch (MUST)

**Query Purpose:** Retrieves the current Babylon epoch number, which is
essential for timestamping public randomness commitments.

**Query Interface:**
```rust
// Request - no parameters required
pub struct CurrentEpochRequest {}

// Response
pub struct CurrentEpochResponse {
    pub epoch: u64,
}
```

**Expected Behaviour:**
- Query the current epoch from the Babylon chain
- Return the current epoch number as a `u64`

**Usage Context:** This query is used when storing public randomness commitments
to record the Babylon epoch at which the commitment was made, enabling BTC
timestamping validation.

#### 4.3.2. LastFinalizedEpoch (MUST)

**Query Purpose:** Retrieves the last finalized Babylon epoch, which is used to
verify that public randomness commitments have been timestamped by Bitcoin.

**Query Interface:**
```rust
// Request - no parameters required  
pub struct LastFinalizedEpochRequest {}

// Response
pub struct LastFinalizedEpochResponse {
    pub epoch_number: u64,
    pub epoch_info: Option<EpochInfo>,
}

pub struct EpochInfo {
    pub epoch_number: u64,
    pub epoch_boundary: u64,
    pub sealed_epoch: u64,
}
```

**Expected Behaviour:**
- Query the latest finalized epoch information from the Babylon chain
- Return the epoch number and optional epoch metadata

**Usage Context:** This query is used during finality signature verification to
ensure that the public randomness commitment has been timestamped by Bitcoin
before accepting finality signatures that reference it.

**BTC Timestamping Validation:** A public randomness commitment is considered
BTC-timestamped if its commitment epoch is less than or equal to the last
finalized epoch. This ensures that the commitment has been anchored to the
Bitcoin blockchain before being used for finality signatures.

### 4.4. Contract Instantiation

Finality contracts MUST support instantiation with configuration parameters for
operational settings. The contract MUST utilize custom queries provided by the
[babylon-bindings](https://github.com/babylonlabs-io/bindings/) crate to
interact with Babylon-specific functionality.

```rust
pub struct InstantiateMsg {
    pub admin: String,
    pub bsn_id: String,
    pub min_pub_rand: u64,
    pub rate_limiting_interval: u64,
    pub max_msgs_per_interval: u32,
    pub allowed_finality_providers: Option<Vec<String>>,
}
```

**New Optional Parameter:**
- `allowed_finality_providers`: `Option<Vec<String>>` — An optional list of BTC public keys (hex-encoded) to pre-populate the allowlist at contract instantiation. If provided, each key must be non-empty. Any empty key will cause instantiation to fail. If omitted or empty, the allowlist will start empty.

**Example:**
```json
{
  "admin": "babylon1...",
  "bsn_id": "op-stack-l2-11155420",
  "min_pub_rand": 100,
  "rate_limiting_interval": 500,
  "max_msgs_per_interval": 10,
  "allowed_finality_providers": [
    "02a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
    "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
  ]
}
```

**Expected Behaviour:** When deploying the finality contract, the following
parameters must be provided:

**Required Parameters:**
- `admin`: String - The initial admin address for the contract who can update
  settings
- `bsn_id`: String - The unique identifier for this BSN (e.g.,
  `op-stack-l2-11155420`)
- `min_pub_rand`: u64 - Minimum number of public randomness values required in
  commitments (must be ≥ 1)
- `rate_limiting_interval`: u64 - Number of blocks in each rate limiting
  interval (must be ≥ 1)
- `max_msgs_per_interval`: u32 - Maximum messages allowed per finality provider
  per interval (must be ≥ 1)

**Validation Requirements:**
1. **Admin Address Validation**: The `admin` parameter MUST be a valid Babylon address
2. **BSN ID Validation**: The `bsn_id` parameter MUST:
   - Not be empty
   - Contain only alphanumeric characters, hyphens, and underscores
   - Not exceed 100 characters in length
3. **Min Pub Rand Validation**: The `min_pub_rand` parameter MUST be ≥ 1
4. **Rate Limiting Validation**: Both `rate_limiting_interval` and
5. **Allowlist Validation**: If `allowed_finality_providers` is provided, all keys MUST be non-empty strings. If any are empty, instantiation MUST fail.
   `max_msgs_per_interval` MUST be ≥ 1

**Instantiation Process:**
1. **Parameter Validation**: Validate all input parameters according to the
   requirements above
2. **Admin Setup**: Set the provided admin address as the contract administrator
3. **Configuration Storage**: Save the bsn_id, min_pub_rand, and rate limiting
4. **Allowlist Setup**: If provided, add all valid keys to the allowlist
   configuration in the contract configuration
5. **Response**: Return a success response with instantiation attributes

### 4.5. Signing Context

Finality contracts MUST implement signing context to ensure message signatures
are bound to the specific contract and chain. The signing context prevents
signature replay attacks across different contracts or chains.
[Babylon](https://github.com/babylonlabs-io/babylon/tree/main/app/signingcontext)
provides a library for signing context.

**Signing Context Format:** The signing context is a hex-encoded SHA256 hash of
a structured string that includes:
- Protocol name: `btcstaking`
- Version: `0`
- Operation type: `fp_rand_commit` or `fp_fin_vote`
- Chain ID: The chain ID of the blockchain where the contract is deployed
- Contract address: The address of the finality contract

**Context Generation:**
1. **Public Randomness Commitment Context**:
   ```
   hex(sha256("btcstaking/0/fp_rand_commit/{chain_id}/{contract_address}"))
   ```
   Used for verifying signatures on public randomness commitments.

2. **Finality Vote Context**:
   ```
   hex(sha256("btcstaking/0/fp_fin_vote/{chain_id}/{contract_address}"))
   ```
   Used for verifying EOTS signatures on finality votes.

**Usage in Message Construction:** The signing context is prepended to the
message being signed as raw bytes from the hex string. This ensures that
signatures are cryptographically bound to the specific contract instance and
cannot be replayed across different contracts or chains.

### 4.6. Rate Limiting (MUST)

Finality contracts MUST implement rate limiting to prevent spam and ensure fair
usage of the contract by finality providers. The rate limiting system operates
on a per-finality provider basis using block intervals.

**Rate Limiting Design:**
- **Interval-Based**: Rate limits are calculated based on block intervals, where
  each interval consists of a configurable number of Babylon blocks
- **Per-Finality Provider**: Each finality provider has an independent rate
  limit counter
- **Automatic Reset**: Counters automatically reset when a new interval begins
- **Configurable Limits**: Both the interval duration and maximum messages per
  interval are configurable at contract instantiation

**Rate Limiting Configuration:**
```rust
pub struct RateLimitingConfig {
    pub max_msgs_per_interval: u32,  // Maximum messages per FP per interval
    pub block_interval: u64,         // Number of Babylon blocks per interval
}
```

**Rate Limiting Storage:**
- **Storage Key**: `Map<&[u8], (u64, u32)>` where the key is the finality
  provider's BTC public key
- **Storage Value**: Tuple of `(interval_number, message_count)` where:
  - `interval_number`: The current interval number (calculated as `block_height
    / block_interval`)
  - `message_count`: Number of messages processed in the current interval

**Rate Limiting Logic:**
1. **Interval Calculation**: `current_interval = block_height / block_interval`
2. **Counter Retrieval**: Load existing counter for the finality provider or
   initialize with `(current_interval, 0)`
3. **Interval Reset Check**: If stored interval differs from current interval,
   reset count to 0 and update interval
4. **Rate Limit Check**: Verify that `message_count + 1 ≤
   max_msgs_per_interval`
5. **Counter Update**: Increment the message count and save to storage
6. **Error Handling**: Return `ContractError::RateLimitExceeded` if the limit
   would be exceeded

**Integration Points:**
- MUST be enforced in `CommitPublicRandomness` handler before signature
  verification
- MUST be enforced in `SubmitFinalitySignature` handler before finality
  signature processing
- Rate limiting checks MUST occur early in message processing to prevent
  resource consumption

**Rate Limiting Errors:**
```rust
ContractError::RateLimitExceeded {
    fp_btc_pk: String,     // Hex-encoded finality provider BTC public key
    limit: u32,            // The rate limit that was exceeded
}
```

### 4.7. Finality Contract message handlers

The finality contract message requirements are divided into core finality
functionality (MUST) and administrative functionality (SHOULD):

```rust
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Binary};
use babylon_merkle::Proof;

#[cw_serde]
pub enum ExecuteMsg {
    // MUST: Core messages

    /// This message allows a finality provider to commit to a sequence of public randomness values
    /// that will be revealed later during finality signature submissions.
    /// 
    /// The commitment is a Merkle root containing the public randomness values. When submitting 
    /// finality signatures later, the provider must include Merkle proofs that verify against this
    /// commitment.
    ///
    /// This commitment mechanism ensures that finality providers cannot adaptively choose their
    /// public randomness values after seeing block contents, which is important for security.
    CommitPublicRandomness {
        /// `fp_pubkey_hex` is the BTC PK of the finality provider that commits the public randomness
        fp_pubkey_hex: String,
        /// `start_height` is the start block height of the list of public randomness
        start_height: u64,
        /// `num_pub_rand` is the amount of public randomness committed
        num_pub_rand: u64,
        /// `commitment` is the commitment of these public randomness values.
        /// Currently, it's the root of the Merkle tree that includes the public randomness
        commitment: Binary,
        /// `signature` is the signature on (start_height || num_pub_rand || commitment) signed by
        /// the SK corresponding to `fp_pubkey_hex`.
        /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
        signature: Binary,
    },
    /// Submit Finality Signature.
    ///
    /// This is a message that can be called by a finality provider to submit their finality
    /// signature to the BSN.
    /// The signature is verified by the BSN using the finality provider's public key.
    /// If an equivocation is detected (signing two different blocks at the same height),
    /// the contract will automatically extract the secret key using EOTS and submit evidence
    /// to Babylon Genesis for slashing.
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    SubmitFinalitySignature {
        /// The BTC public key of the finality provider submitting the signature
        fp_pubkey_hex: String,
        /// Optional L1 block number (rollup-specific metadata)
        l1_block_number: Option<u64>,
        /// Optional L1 block hash hex (rollup-specific metadata)
        l1_block_hash_hex: Option<String>,
        /// The block height this finality signature is for
        height: u64,
        /// The public randomness used for signing this block
        pub_rand: Binary,
        /// Merkle proof verifying that pub_rand was included in the earlier commitment
        proof: Proof,
        /// Hash of the block being finalized
        block_hash: Binary,
        /// Finality signature on (height || block_hash) signed by finality provider
        signature: Binary,
    },

    // SHOULD: Administrative messages

    /// Update the admin address.
    ///
    /// This message can be called by the admin only.
    /// The new admin address must be a valid Babylon address.
    UpdateAdmin {
        admin: String,
    },
    /// Add a finality provider to the allowlist.
    ///
    /// This message can be called by the admin only.
    /// Only finality providers in the allowlist can submit finality signatures and public randomness commitments.
    AddToAllowlist {
        /// The BTC public key of the finality provider to add to the allowlist (in hex format)
        fp_pubkey_hex: String,
    },
    /// Remove a finality provider from the allowlist.
    ///
    /// This message can be called by the admin only.
    /// Removing a finality provider from the allowlist will prevent them from submitting
    /// new finality signatures and public randomness commitments.
    RemoveFromAllowlist {
        /// The BTC public key of the finality provider to remove from the allowlist (in hex format)
        fp_pubkey_hex: String,
    },
}
```

#### 4.7.1. CommitPublicRandomness (MUST)

**Message Structure:**
```rust
CommitPublicRandomness {
    fp_pubkey_hex: String,
    start_height: u64,
    num_pub_rand: u64,
    commitment: Binary,
    signature: Binary,
}
```

**Expected Behaviour:** Finality contracts MUST implement this handler with the
following verification logic:

1. **Rate Limiting Check**: Enforce rate limiting for the finality provider:
   - Call the rate limiting function with the finality provider's BTC public
     key and current block environment
   - Return `ContractError::RateLimitExceeded` if the rate limit is exceeded
   - This check MUST occur before any other validation to prevent resource
     consumption

2. **Finality Provider Existence Check**: Verify that the finality provider
   exists and is not slashed by querying the Babylon Genesis chain through gRPC:
   - Use `query_grpc` to call `/babylon.btcstaking.v1.Query/FinalityProvider`
     with the `fp_pubkey_hex` parameters
   - Verify the response contains a valid finality provider
   - Ensure the finality provider is associated with this BSN
   - Ensure the finality provider has not been slashed (`slashed_babylon_height`
     and `slashed_btc_height` are both 0)

2. **Allowlist Check**: Verify that the finality provider is in the allowlist:
   - Query the allowlist storage to check if the finality provider's BTC public key is allowed
   - If the finality provider is not in the allowlist, return `FinalityProviderNotAllowed` error

3. **Signature Verification**: Verify the commitment signature using Schnorr
   signature verification:
   - Decode the finality provider's BTC public key from `fp_pubkey_hex`
     parameter
   - Generate signing context:
     `hex(sha256("btcstaking/0/fp_rand_commit/{chain_id}/{contract_address}"))`
   - Construct message: `signing_context || start_height || num_pub_rand ||
     commitment` (where
     signing_context is the hex string as bytes, start_height and num_pub_rand
     are in big-endian bytes)
   - Verify signature against the constructed message using the BTC public key

4. **Height Overlap Check**: Ensure no overlap with existing public randomness
   commitments:
   - Query the last public randomness commitment for this finality provider from
     public randomness commitment state
   - Use key `(fp_pubkey_hex, _)` to find the highest height commitment
   - Ensure `start_height > last_commit.start_height + last_commit.num_pub_rand
     - 1` to prevent overlapping ranges

5. **Storage Operations**: Save the public randomness commitment data:
   - Create a new `PubRandCommit` struct with provided parameters and current
     Babylon epoch
   - Save to the public randomness commitment state using key `(fp_pubkey_hex,
     start_height)`
   - Record the current Babylon epoch as the commitment epoch for BTC
     timestamping validation

#### 4.7.2. SubmitFinalitySignature (MUST)

**Message Structure:**
```rust
SubmitFinalitySignature {
    fp_pubkey_hex: String,
    l1_block_number: Option<u64>,
    l1_block_hash_hex: Option<String>,
    height: u64,
    pub_rand: Binary,
    proof: Proof,
    block_hash: Binary,
    signature: Binary,
}
```

**Finality Signature Message Format:** The finality signature is computed over a
message constructed as follows:
1. Generate signing context:
   `hex(sha256("btcstaking/0/fp_fin_vote/{chain_id}/{contract_address}"))`
2. Construct the message: `signing_context || height || block_hash` (where
signing_context is the hex string as bytes, height is encoded as 8 bytes in
big-endian format) 3. Apply SHA256 hash to the message: `message_hash =
SHA256(signing_context || height || block_hash)`
4. Sign the message hash using EOTS with the public randomness

**Expected Behaviour:** Finality contracts MUST implement this handler with the
following verification logic:

1. **Rate Limiting Check**: Enforce rate limiting for the finality provider:
   - Call the rate limiting function with the finality provider's BTC public
     key and current block environment
   - Return `ContractError::RateLimitExceeded` if the rate limit is exceeded
   - This check MUST occur before any other validation to prevent resource
     consumption

2. **Finality Provider Existence Check**: Verify that the finality provider
   exists and is not slashed by querying the Babylon Genesis chain through gRPC:
   - Use `query_grpc` to call `/babylon.btcstaking.v1.Query/FinalityProvider`
     with the `bsn_id` parameters
   - Verify the response contains a valid finality provider
   - Ensure the finality provider is associated with this BSN
   - Ensure the finality provider has not been slashed (`slashed_babylon_height`
     and `slashed_btc_height` are both 0)

2. **Allowlist Check**: Verify that the finality provider is in the allowlist:
   - Query the allowlist storage to check if the finality provider's BTC public key is allowed
   - If the finality provider is not in the allowlist, return `FinalityProviderNotAllowed` error

3. **Duplicate Vote Check**: Check if an identical vote already exists:
   - Query finality signature state using key `(height, fp_pubkey_hex)`
   - If the same signature exists for the same block hash, return success
     (duplicate vote)
   - If a different signature exists for the same height, proceed to
     equivocation handling

4. **Public Randomness Commitment Retrieval**: Find the public randomness
   commitment that covers the target height:
   - Query public randomness commitment state to find commitment where
     `start_height <= height <= start_height + num_pub_rand - 1`
   - **BTC Timestamping Validation**: Ensure the commitment is timestamped by
     BTC by verifying that the commitment's epoch is less than or equal to the
     last finalized epoch
   - Use the commitment for subsequent verification steps

5. **Finality Signature Verification**:
   - Verify `height == pr_commit.start_height + proof.index`
   - Verify `proof.total == pr_commit.num_pub_rand`
   - Verify the inclusion proof for the public randomness value against
     `pr_commit.commitment`
   - Verify the EOTS signature using:
     - Generate signing context:
       `hex(sha256("btcstaking/0/fp_fin_vote/{chain_id}/{contract_address}"))`
     - Message: `SHA256(signing_context || height || block_hash)` (where
       signing_context is the hex string as bytes, height is in big-endian
       format)
     - Public randomness value and EOTS signature

6. **Equivocation Detection and Handling**: Check if the finality provider has
   already voted for a different block at this height:
   - If existing signature differs from current block hash:
     - Extract the secret key using EOTS from the two different signatures
     - Send `BabylonMsg::MsgEquivocationEvidence` to trigger slashing on Babylon
       Genesis
     - Emit `slashed_finality_provider` event with extracted secret key

7. **Storage Operations**: Store the finality signature and related data
   atomically:
   - Use the `insert_finality_sig_and_signatory` helper function to perform all
     storage operations atomically
   - This function performs the following operations in sequence:
     - Save finality signature using key `(height, fp_pubkey_hex)` (will
       override existing signature)
     - Add signatory to the set of signatories for the block using key `(height,
       block_hash)`
     - Save public randomness value using key `(height, fp_pubkey_hex)` if this
       is the first vote for this height


#### 4.7.3. UpdateAdmin (SHOULD)

**Message Structure:**
```rust
UpdateAdmin {
    admin: String,
}
```

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
handler with the following verification logic:

1. **Admin Authorization**: Verify that the caller is the current contract
   admin:
   - Query the current admin address
   - Verify that the message sender matches the current admin address

2. **Admin Validation**: Validate the new admin address:
   - Ensure the `admin` parameter is a valid Babylon address
   - Optionally ensure the new admin differs from the current admin

3. **Storage Operations**: Update the admin address:
   - Update the admin address using the cw-controllers Admin functionality
   - The new admin address from `admin` parameter replaces the current admin
   - Return success response

#### 4.5.4. AddToAllowlist (SHOULD)

**Message Structure:**
```rust
AddToAllowlist {
    fp_pubkey_hex: String,
}
```

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
handler with the following verification logic:

1. **Admin Authorization**: Verify that the caller is the current contract
   admin:
   - Query the current admin address
   - Verify that the message sender matches the current admin address

2. **Parameter Validation**: Validate the finality provider public key:
   - Ensure the `fp_pubkey_hex` parameter is not empty
   - If empty, return `EmptyFpBtcPubKey` error

3. **Storage Operations**: Add the finality provider to the allowlist:
   - Add the finality provider's BTC public key to the allowlist storage
   - Return success response with action attributes

#### 4.5.5. RemoveFromAllowlist (SHOULD)

**Message Structure:**
```rust
RemoveFromAllowlist {
    fp_pubkey_hex: String,
}
```

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
handler with the following verification logic:

1. **Admin Authorization**: Verify that the caller is the current contract
   admin:
   - Query the current admin address
   - Verify that the message sender matches the current admin address

2. **Parameter Validation**: Validate the finality provider public key:
   - Ensure the `fp_pubkey_hex` parameter is not empty
   - If empty, return `EmptyFpBtcPubKey` error

3. **Storage Operations**: Remove the finality provider from the allowlist:
   - Remove the finality provider's BTC public key from the allowlist storage
   - Return success response with action attributes

#### 4.7.4. PruneData (SHOULD)

**Message Structure:**
```rust
PruneData {
    rollup_height: u64,
    max_signatures_to_prune: Option<u32>,
    max_pub_rand_values_to_prune: Option<u32>,
}
```

**Parameter Semantics:**
- `rollup_height`: Remove all data for rollup blocks with height ≤ this value.
- `max_signatures_to_prune`: Maximum number of finality signatures and signatories to prune in a single operation.
  - Since every signature has a corresponding signatory record, this limit applies to both.
  - If `None`, the default value is 50.
  - If `Some(0)`, disables pruning of finality signatures and signatories for this call.
- `max_pub_rand_values_to_prune`: Maximum number of public randomness values to prune in a single operation.
  - If `None`, the default value is 50.
  - If `Some(0)`, disables pruning of public randomness values for this call.

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
handler with the following logic:

1. **Admin Authorization**: Verify that the caller is the current contract
   admin:
   - Query the current admin address
   - Verify that the message sender matches the current admin address

2. **Parameter Validation**: Validate pruning parameters:
   - Ensure `rollup_height` is reasonable (not excessively high)
   - Apply default limits if `None` provided (50 for both types)
   - Apply maximum limits to prevent gas exhaustion (100 for both types)

3. **Pruning Operations**: Remove old data for blocks with height ≤
   `rollup_height`:
   - **Finality Signatures**: Remove entries from `FINALITY_SIGNATURES` storage
     up to `max_signatures_to_prune` limit
   - **Signatories**: Remove entries from `SIGNATORIES_BY_BLOCK_HASH` storage
     up to the same limit (one-to-one correspondence with signatures)
   - **Public Randomness Values**: Remove entries from `PUB_RAND_VALUES`
     storage up to `max_pub_rand_values_to_prune` limit

4. **Response Attributes**: Return response with pruning statistics:
   - `pruned_signatures`: Number of finality signatures removed
   - `pruned_signatories`: Number of signatory entries removed
   - `pruned_pub_rand_values`: Number of public randomness values removed

**WARNING**: This operation is irreversible. The admin is responsible for
ensuring that the pruning height is safe and that no data is still being used
for the affected height range.

**Example Usage:**
```json
{
  "prune_data": {
    "rollup_height": 1000,
    "max_signatures_to_prune": 50,
    "max_pub_rand_values_to_prune": 20
  }
}
```

### 4.8. Contract State Storage

This section documents the actual state storage structure used by the finality
contract implementation.

#### 4.8.1. Core Configuration

**ADMIN**: Admin controller for contract administration
- Type: `Admin` (from cw-controllers)
- Storage key: `"admin"`
- Purpose: Manages contract administrative functions

**CONFIG**: Contract configuration settings
- Type: `Item<Config>`
- Storage key: `"config"`
- Structure:
  ```rust
  pub struct Config {
      pub bsn_id: String,
      pub min_pub_rand: u64,
      pub rate_limiting: RateLimitingConfig,
  }

  pub struct RateLimitingConfig {
      pub max_msgs_per_interval: u32,
      pub block_interval: u64,
  }
  ```

**ALLOWED_FINALITY_PROVIDERS**: Allowlist of finality providers
- Type: `Map<String, bool>`
- Storage key: `"allowed_finality_providers"`
- Key format: `fp_pubkey_hex` (BTC public key in hex format)
- Purpose: Stores the set of finality providers that are allowed to submit finality signatures and public randomness commitments
- Value: `true` for all entries (boolean flag for consistency)

#### 4.8.2. Rate Limiting Storage

**NUM_MSGS_LAST_INTERVAL**: Rate limiting counters per finality provider
- Type: `Map<&[u8], (u64, u32)>`
- Storage key: `"num_msgs_last_interval"`
- Key format: `fp_pubkey_bytes`
- Value format: `(interval_number, message_count)`
- Purpose: Tracks message count per finality provider within block intervals
- Automatic reset when interval changes

#### 4.8.3. Finality State Storage

**FINALITY_SIGNATURES**: Finality signatures by height and provider
- Type: `Map<(u64, &[u8]), FinalitySigInfo>`
- Storage key: `"finality_signatures"`
- Key format: `(block_height, fp_pubkey_bytes)`
- Purpose: Stores finality signature information including signature and block
  hash
- Structure:
  ```rust
  pub struct FinalitySigInfo {
      pub finality_sig: Vec<u8>,  // The EOTS finality signature
      pub block_hash: Vec<u8>,    // The block hash that the signature is for
  }
  ```

**SIGNATORIES_BY_BLOCK_HASH**: Voting aggregation by height and block hash
- Type: `Map<(u64, &[u8]), HashSet<String>>`
- Storage key: `"signatories_by_block_hash"`
- Key format: `(block_height, block_hash_bytes)`
- Purpose: Maps each (height, block_hash) combination to the set of finality
  provider public keys (hex-encoded) that voted for it

#### 4.8.4. Public Randomness Storage

**PUB_RAND_VALUES**: Individual public randomness values
- Type: `Map<(u64, &[u8]), Vec<u8>>`
- Storage key: `"pub_rand_values"`
- Key format: `(block_height, fp_pubkey_bytes)`
- Purpose: Stores individual public randomness values revealed during finality
  signature submission
- **Note**: Key format changed from `(&[u8], u64)` to `(u64, &[u8])` for
  efficient range queries in pruning operations

**PUB_RAND_COMMITS**: Public randomness commitments by finality provider
- Type: `Map<(&[u8], u64), PubRandCommit>`
- Storage key: `"pub_rand_commits"`
- Key format: `(fp_pubkey_bytes, start_height)`
- Purpose: Stores public randomness commitments made by finality providers
- Structure:
  ```rust
  pub struct PubRandCommit {
      pub start_height: u64,
      pub num_pub_rand: u64,
      pub babylon_epoch: u64,
      pub commitment: Vec<u8>,
  }
  ```

### 4.9. Finality contract queries

The finality contract query requirements are divided into core finality
functionality (MUST) and administrative functionality (SHOULD):

```rust
use cosmwasm_schema::{cw_serde, QueryResponses};
use cw_controllers::AdminResponse;
use std::collections::HashSet;

#[cw_serde]
pub struct BlockVoterInfo {
    pub fp_btc_pk_hex: String,
    pub pub_rand: Vec<u8>,
    pub finality_signature: FinalitySigInfo,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {    
    // MUST: Core finality queries
    #[returns(Option<Vec<BlockVoterInfo>>)]
    BlockVoters { height: u64, hash_hex: String },
    /// `FirstPubRandCommit` returns the first public random commitment (if any) for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    FirstPubRandCommit { btc_pk_hex: String },
    /// `LastPubRandCommit` returns the last public random commitment (if any) for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    #[returns(Option<PubRandCommit>)]
    LastPubRandCommit { btc_pk_hex: String },
    /// `ListPubRandCommit` returns a paginated list of public randomness 
    /// commitments for a given FP.
    ///
    /// `btc_pk_hex` is the BTC public key of the finality provider, in hex format.
    /// `start_after` is optional pagination parameter - only return commitments 
    /// with start_height > start_after.
    /// `limit` is optional limit on number of results (default 10, max 30).
    /// `reverse` is optional flag to reverse the order (default false = 
    /// ascending by start_height).
    #[returns(Vec<PubRandCommit>)]
    ListPubRandCommit { 
        btc_pk_hex: String, 
        start_after: Option<u64>, 
        limit: Option<u32>, 
        reverse: Option<bool> 
    },

    // SHOULD: Administrative queries
    #[returns(AdminResponse)]
    Admin {},
    #[returns(Config)]
    Config {},
    /// Get the list of all allowed finality providers.
    ///
    /// Returns a list of BTC public keys (in hex format) of finality providers
    /// that are allowed to submit finality signatures and public randomness commitments.
    #[returns(Vec<String>)]
    AllowedFinalityProviders {},

}
```

#### 4.9.1. BlockVoters (MUST)

**Query Structure:**
```rust
BlockVoters {
    height: u64,         // Block height to query voters for
    hash_hex: String     // Block hash in hex format
}
```

**Return Type:** `Option<Vec<BlockVoterInfo>>` - List of finality providers and
their signatures for the specified block, or `None` if no votes found.

**Expected Behaviour:** Finality contracts MUST implement this query to return
the finality providers that voted for a specific block along with their complete
signature information:

1. Decode hash_hex from hex string to bytes
   - IF decode fails: RETURN error with `QueryBlockVoterError`

2. Query signatories storage using key (height, hash_bytes)
   - Access the stored set of finality provider public keys from
     `SIGNATORIES_BY_BLOCK_HASH`

3. For each finality provider in the set:
   - Query the `FINALITY_SIGNATURES` storage using key (height, fp_pubkey_bytes)
   - IF signature not found: RETURN error with `QueryBlockVoterError`
   - Query the `PUB_RAND_VALUES` storage using key (fp_pubkey_bytes, height)
   - IF public randomness not found: RETURN error with `QueryBlockVoterError`
   - Create BlockVoterInfo with fp_btc_pk_hex, pub_rand, and FinalitySigInfo

4. Return the list of BlockVoterInfo
   - IF no votes found: RETURN `None`
   - IF votes exist: RETURN `Some(Vec<BlockVoterInfo>)` with all voter
     information

WHERE BlockVoterInfo contains:
- `fp_btc_pk_hex`: `String` - The finality provider's BTC public key in hex
  format
- `pub_rand`: `Vec<u8>` - The public randomness value for the block
- `finality_signature`: `FinalitySigInfo` - Complete signature information
  including signature and block hash

#### 4.9.2. FirstPubRandCommit (MUST)

**Query Structure:**
```rust
FirstPubRandCommit {
    btc_pk_hex: String    // BTC public key of the finality provider in hex format
}
```

**Return Type:** `Option<PubRandCommit>` - The first public randomness
commitment or None if not found

**Expected Behaviour:** Finality contracts MUST implement this query to return
the first public randomness commitment for a given finality provider:

1. Query public randomness commitments storage with prefix btc_pk_hex
   - Search for all commitments belonging to this finality provider

2. Sort commitments by start_height in ascending order
   - Find the commitment with the lowest start_height

3. Return the first commitment
   - IF no commitments found: RETURN `None`
   - IF commitments exist: RETURN `Some(first_commitment)`

WHERE PubRandCommit contains:
- `start_height`: `u64`
- `num_pub_rand`: `u64`
- `babylon_epoch`: `u64`
- `commitment`: `Vec<u8>`

#### 4.9.3. LastPubRandCommit (MUST)

**Query Structure:**
```rust
LastPubRandCommit {
    btc_pk_hex: String    // BTC public key of the finality provider in hex format
}
```

**Return Type:** `Option<PubRandCommit>` - The last public randomness commitment
or `None` if not found

**Expected Behaviour:** Finality contracts MUST implement this query to return
the last public randomness commitment for a given finality provider:

1. Query public randomness commitments storage with prefix btc_pk_hex
   - Search for all commitments belonging to this finality provider

2. Sort commitments by start_height in descending order
   - Find the commitment with the highest start_height

3. Return the last commitment
   - IF no commitments found: RETURN `None`
   - IF commitments exist: RETURN `Some(last_commitment)`

WHERE PubRandCommit contains:
- `start_height`: `u64`
- `num_pub_rand`: `u64`
- `babylon_epoch`: `u64`
- `commitment`: `Vec<u8>`

#### 4.9.4. ListPubRandCommit (MUST)

**Query Structure:**
```rust
ListPubRandCommit {
    btc_pk_hex: String,         // BTC public key of the finality provider
    start_after: Option<u64>,   // Pagination: start_height > start_after
    limit: Option<u32>,         // Limit results (default 10, max 30)
    reverse: Option<bool>,      // Reverse order (default false)
}
```

**Return Type:** `Vec<PubRandCommit>` - A paginated list of public randomness
commitments, or empty vector if none found

**Expected Behaviour:** Finality contracts MUST implement this query to return a
paginated list of public randomness commitments for a given finality provider:

1. Query public randomness commitments storage with prefix btc_pk_hex
   - Search for all commitments belonging to this finality provider
   - Apply pagination using start_after as exclusive boundary if provided

2. Apply sorting and limiting
   - Sort commitments by start_height in ascending order (or descending if
     reverse=true)
   - Limit results to the specified limit (default 10, max 30)

3. Return the paginated results
   - IF no commitments found: RETURN empty vector
   - IF commitments exist: RETURN `Vec<PubRandCommit>` with matching commitments

WHERE PubRandCommit contains:
- `start_height`: `u64`
- `num_pub_rand`: `u64`
- `babylon_epoch`: `u64`
- `commitment`: `Vec<u8>`

#### 4.9.5. Admin (SHOULD)

**Query Structure:**
```rust
Admin {}    // No parameters required
```

**Return Type:** `AdminResponse` - Contains the current admin address

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
query to return the current admin address:

1. Query admin storage to retrieve current admin address
   - Access the stored admin address value

2. Return admin information
   - Return AdminResponse containing the admin address
   - IF no admin set: RETURN `None`

WHERE AdminResponse contains:
- `admin`: `Option<String>`

#### 4.9.6. Config (SHOULD)

**Query Structure:**
```rust
Config {}    // No parameters required
```

**Return Type:** `Config` - Contract configuration settings

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
query to return the contract configuration:

1. Query configuration storage to retrieve current settings
   - Access all stored configuration parameters

2. Return configuration information
   - Return Config struct with all configuration values
   - All configuration fields should be populated

WHERE Config contains:
- `bsn_id`: `String` - The BSN identifier for this finality contract
- `min_pub_rand`: `u64` - Minimum public randomness requirement for commitments
- `rate_limiting`: `RateLimitingConfig` - Rate limiting configuration including
  `max_msgs_per_interval` and `block_interval`

#### 4.9.7. AllowedFinalityProviders (SHOULD)

**Query Structure:**
```rust
AllowedFinalityProviders {}    // No parameters required
```

**Return Type:** `Vec<String>` - List of BTC public keys (in hex format) of allowed finality providers

**Expected Behaviour:** Finality contracts SHOULD implement this administrative
query to return the list of all allowed finality providers:

1. Query allowlist storage to retrieve all allowed finality providers
   - Access all entries in the `ALLOWED_FINALITY_PROVIDERS` storage

2. Return allowlist information
   - Return a vector of BTC public keys (in hex format) for all allowed finality providers
   - If no finality providers are in the allowlist, return an empty vector

WHERE the return value contains:
- `Vec<String>` - List of BTC public keys in hex format for all allowed finality providers

## 5. Implementation status

### 5.1. Babylon implementation status

The interfaces in this specification have been fully implemented in the [Babylon
codebase](https://github.com/babylonlabs-io/babylon) (`main` branch). This
includes all required message types, queries, and expected behaviors for
finality contract integration.

### 5.2. Finality contract implementation status

As of this writing, there are two known implementations of finality contracts
that integrate with Babylon's Bitcoin staking protocol:

1. **OP Finality Gadget** - Available at
   [babylonlabs-io/rollup-bsn-contracts](https://github.com/babylonlabs-io/rollup-bsn-contracts).
   This implementation is a CosmWasm smart contract designed to integrate OP
   Stack rollups with Babylon's Bitcoin staking protocol. The contract is
   actively developed and maintained by Babylon Labs. This implementation
   follows the specification outlined in this document.

2. **BLITZ** - Available at
   [alt-research/blitz](https://github.com/alt-research/blitz). This
   implementation provides fast finality for Arbitrum Orbit chains using
   Babylon's Bitcoin staking protocol. BLITZ includes both the finality contract
   (`nitro-finality-gadget`) and support infrastructure for Arbitrum Orbit
   integration. The project is developed and maintained by AltLayer.

**Comparison**: While both implementations follow the general principles
outlined in this specification, they target different rollup architectures. The
OP Finality Gadget is specifically designed for OP Stack chains and leverages
CosmWasm for deployment on Babylon, whereas BLITZ focuses on Arbitrum Orbit
chains and includes additional infrastructure components for the Nitro-based
architecture.
<!-- TODO: add Manta contract after open-source -->
