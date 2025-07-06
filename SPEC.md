# Finality contract specification for the rollup integration

- [1. Changelog](#1-changelog)
- [2. Abstract](#2-abstract)
- [3. Background](#3-background)
  - [3.1. BTC staking integration](#31-btc-staking-integration)
  - [3.2. The role of the finality contract](#32-the-role-of-the-finality-contract)
- [4. Keywords](#4-keywords)
- [5. Specification](#5-specification)
  - [5.1. Babylon Genesis chain message interfaces](#51-babylon-genesis-chain-message-interfaces)
    - [5.1.1. Message: EquivocationEvidence (MUST)](#511-message-equivocationevidence-must)
  - [5.2. Babylon Genesis chain gRPC queries](#52-babylon-genesis-chain-grpc-queries)
    - [5.2.1. QueryFinalityProvider (MUST)](#521-queryfinalityprovider-must)
  - [5.3. Contract Instantiation](#53-contract-instantiation)
  - [5.4. Finality Contract message handlers](#54-finality-contract-message-handlers)
    - [5.4.1. CommitPublicRandomness (MUST)](#541-commitpublicrandomness-must)
    - [5.4.2. SubmitFinalitySignature (MUST)](#542-submitfinalitysignature-must)
    - [5.4.3. Slashing (MUST)](#543-slashing-must)
    - [5.4.4. SetEnabled (SHOULD)](#544-setenabled-should)
    - [5.4.5. UpdateAdmin (SHOULD)](#545-updateadmin-should)
  - [5.5. Contract State Storage](#55-contract-state-storage)
    - [5.5.1. Core Configuration](#551-core-configuration)
    - [5.5.2. Finality State Storage](#552-finality-state-storage)
    - [5.5.3. Public Randomness Storage](#553-public-randomness-storage)
  - [5.6. Finality contract queries](#56-finality-contract-queries)
    - [5.6.1. BlockVoters (MUST)](#561-blockvoters-must)
    - [5.6.2. FirstPubRandCommit (MUST)](#562-firstpubrandcommit-must)
    - [5.6.3. LastPubRandCommit (MUST)](#563-lastpubrandcommit-must)
    - [5.6.4. Admin (SHOULD)](#564-admin-should)
    - [5.6.5. Config (SHOULD)](#565-config-should)
    - [5.6.6. IsEnabled (SHOULD)](#566-isenabled-should)
- [6. Implementation status](#6-implementation-status)
  - [6.1. Babylon implementation status](#61-babylon-implementation-status)
  - [6.2. Finality contracct implementation status](#62-finality-contracct-implementation-status)

## 1. Changelog

- 29-05-2025: Initial draft.

## 2. Abstract

This document specifies the design and requirements of the finality contract used in
integrating rollups with Babylon's Bitcoin staking protocol. The finality
contract enables BSNs to inherit Bitcoin-backed economic security by recording
finality signatures from BSN finality providers, enforcing slashing for
equivocation, and exposing finality signatures to the integrated BSN. The
document details the contract's interfaces, message handlers, and queries, and
provides guidance for implementers seeking to leverage Babylon's Bitcoin
security for rollup finality.

## 3. Background

### 3.1. BTC staking integration

Babylon's phase-3 network introduces Bitcoin staking integration to provide
Bitcoin security to other decentralized systems, known as Bitcoin Supercharged
Networks (BSNs), such as L1 blockchains and rollups. This integration enables
BTC stakers to delegate their native BTC to finality providers on BSNs, and each
BSN will leverage this BTC stake for economic security. For more details, see
the [Cosmos integration
1-pager](https://www.notion.so/BTC-staking-integration-for-Cosmos-chains-1-pager-f0574cd4e624475eb00d64912698a38c?pvs=4)
and [OP Stack integration
1-pager](https://www.notion.so/BTC-staking-integration-for-OP-stack-chains-1-pager-16f28a013c55805fbebdec6102b43c92?pvs=4).

### 3.2. The role of the finality contract

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

## 4. Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [RFC
2119](https://www.ietf.org/rfc/rfc2119.html) and [RFC
8174](https://www.ietf.org/rfc/rfc8174.html).

## 5. Specification

This section outlines the detailed requirements for implementing a finality
contract that integrates with Babylon's Bitcoin staking protocol. It covers the
interfaces with Babylon Genesis chain, message handlers, and queries that all
finality contract implementations must or should support. The specification
distinguishes between required ("MUST") and recommended ("SHOULD") components.

### 5.1. Babylon Genesis chain message interfaces

This section outlines the interfaces that Babylon Genesis chain has to implement
and the finality contract needs to interact with.

#### 5.1.1. Message: EquivocationEvidence (MUST)

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
    /// Signing context used for the signatures (hex-encoded)
    signing_context: String,
}
```

**Expected behavior of Babylon Genesis chain:** Upon receiving the message, the
Babylon chain MUST validate the evidence cryptographically, extract the finality
provider's secret key using EOTS, remove them from the active set, set their
voting power to zero, and record the evidence.

**Usage Context:** Finality contracts MUST send this when detecting
double-signing by a finality provider at the same height.

### 5.2. Babylon Genesis chain gRPC queries

The Babylon Genesis chain MUST provide the contracts with access to the
following gRPC endpoints through the whitelist configuration in the [Babylon
chain](https://github.com/babylonlabs-io/babylon/blob/b9774782f38e9758c4f5aafab1e1e45dde0f3838/wasmbinding/grpc_whitelist.go).
<!-- TODO: use a release rather than a commit for the pointer -->

```go
func WhitelistedGrpcQuery() wasmkeeper.AcceptedQueries {
    return wasmkeeper.AcceptedQueries{
        // btcstkconsumer
        "/babylon.btcstkconsumer.v1.Query/FinalityProvider": func() proto.Message {
            return &bsctypes.QueryFinalityProviderResponse{}
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

Query `/babylon.btcstkconsumer.v1.Query/FinalityProvider` returns the finality
provider information for the given consumer and the finality provider BTC PK.

#### 5.2.1. QueryFinalityProvider (MUST)

```protobuf
// QueryFinalityProviderRequest requests information about a finality provider
message QueryFinalityProviderRequest {
  // consumer id is the consumer id this finality provider is registered to
  string consumer_id = 1;
  // fp_btc_pk_hex is the hex str of Bitcoin secp256k1 PK of the finality provider
  string fp_btc_pk_hex = 2;
}

// QueryFinalityProviderResponse contains information about a finality provider
message QueryFinalityProviderResponse {
  // finality_provider contains the FinalityProvider
  FinalityProviderResponse finality_provider = 1;
}

// FinalityProviderResponse defines a finality provider with voting power information.
message FinalityProviderResponse {
  // description defines the description terms for the finality provider.
  cosmos.staking.v1beta1.Description description = 1;
  // commission defines the commission rate of the finality provider.
  string commission = 2;
  // babylon_pk is the Babylon secp256k1 PK of this finality provider
  string addr = 3;
  // btc_pk is the Bitcoin secp256k1 PK of this finality provider
  // the PK follows encoding in BIP-340 spec
  bytes btc_pk = 4;
  // pop is the proof of possession of babylon_pk and btc_pk
  btcstaking.v1.ProofOfPossessionBTC pop = 5;
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
  // voting_power is the voting power of this finality provider at the given height
  uint64 voting_power = 9;
  // consumer_id is the consumer id this finality provider is registered to
  string consumer_id = 10;
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

This query is used for verifying that finality providers exist and have valid
voting power before accepting their finality signatures or public randomness
commitments.

### 5.3. Contract Instantiation

**InstantiateMsg Structure:**
```rust
pub struct InstantiateMsg {
    pub admin: String,
    pub consumer_id: String,
    pub is_enabled: bool,
}
```

**Expected Behavior:** When deploying the finality contract, the following parameters must be provided:

**Required Parameters:**
- `admin`: String - The initial admin address for the contract who can update settings and enable/disable the finality gadget
- `consumer_id`: String - The unique identifier for this consumer chain (e.g., "op-stack-l2-11155420")  
- `is_enabled`: bool - Whether the finality gadget should be enabled at instantiation

**Instantiation Process:**
1. **Admin Setup**: Set the provided admin address as the contract administrator
2. **Configuration Storage**: Save the consumer_id in the contract configuration
3. **State Initialization**: Set the enabled/disabled state based on the is_enabled parameter
4. **Response**: Return a success response with instantiation attributes

### 5.4. Finality Contract message handlers

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
    /// signature to the Consumer chain.
    /// The signature is verified by the Consumer chain using the finality provider's public key.
    /// If an equivocation is detected (signing two different blocks at the same height),
    /// the contract will automatically extract the secret key using EOTS and submit evidence
    /// to Babylon Genesis for slashing.
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    SubmitFinalitySignature {
        /// The BTC public key of the finality provider submitting the signature
        fp_pubkey_hex: String,
        /// The block height this finality signature is for
        height: u64,
        /// The public randomness used for signing this block
        pub_rand: Binary,
        /// Merkle proof verifying that pub_rand was included in the earlier commitment
        proof: Proof,
        /// Hash of the block being finalized
        block_hash_hex: String,
        /// Finality signature on (height || block_hash_hex) signed by finality provider
        signature: Binary,
    },

    /// Set enabled status of the finality contract.
    ///
    /// This message can be called by the admin only.
    /// If disabled, the finality contract and the BTC staking finality will not be used 
    /// by the rollup. Note this should be implemented in the rollup's finality gadget daemon
    /// program and is not enforced by the contract itself.
    SetEnabled {
        enabled: bool,
    },
    /// Update the admin address.
    ///
    /// This message can be called by the admin only.
    /// The new admin address must be a valid Cosmos address.
    UpdateAdmin {
        admin: String,
    },
}
```

#### 5.4.1. CommitPublicRandomness (MUST)

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

**Expected Behavior:** Finality contracts MUST implement this handler with the following verification logic:

1. **Finality Provider Existence Check**: Verify that the finality provider exists by querying the Babylon Genesis chain through gRPC:
   - Use `query_grpc` to call `/babylon.btcstkconsumer.v1.Query/FinalityProvider` with the `consumer_id` and `fp_pubkey_hex` parameters
   - Verify the response contains a valid finality provider with non-zero voting power

2. **Signature Verification**: Verify the commitment signature using Schnorr signature verification:
   - Decode the finality provider's BTC public key from `fp_pubkey_hex` parameter
   - Construct message: `start_height || num_pub_rand || commitment` (all in big-endian bytes)
   - Verify signature against the constructed message using the BTC public key

3. **Height Overlap Check**: Ensure no overlap with existing public randomness commitments:
   - Query the last public randomness commitment for this finality provider from public randomness commitment state
   - Use key `(fp_pubkey_hex, _)` to find the highest height commitment
   - Ensure `start_height > last_commit.start_height + last_commit.num_pub_rand - 1` to prevent overlapping ranges

4. **Storage Operations**: Save the public randomness commitment data:
   - Create a new `PubRandCommit` struct with provided parameters
   - Save to the public randomness commitment state using key `(fp_pubkey_hex, start_height)`
   - Record the current block height as the commitment block height

#### 5.4.2. SubmitFinalitySignature (MUST)

**Message Structure:**
```rust
SubmitFinalitySignature {
    fp_pubkey_hex: String,
    height: u64,
    pub_rand: Binary,
    proof: Proof,
    block_hash_hex: String,
    signature: Binary,
}
```

**Expected Behavior:** Finality contracts MUST implement this handler with the following verification logic:

1. **Finality Provider Existence Check**: Verify that the finality provider exists:
   - Use `query_grpc` to call `/babylon.btcstkconsumer.v1.Query/FinalityProvider` with `consumer_id` and `fp_pubkey_hex` parameters
   - Verify the response contains a valid finality provider with non-zero voting power

2. **Signature Non-Empty Check**: Ensure the signature parameter is not empty

3. **Duplicate Vote Check**: Check if an identical vote already exists:
   - Query finality signature state using key `(height, fp_pubkey_hex)`
   - Query blocks using key `(height, fp_pubkey_hex)`
   - If both exist and match the provided `block_hash_hex` and `signature`, reject as duplicate

4. **Public Randomness Commitment Retrieval**: Find the public randomness commitment that covers the target height:
   - Query public randomness commitment state to find commitment where `start_height <= height <= start_height + num_pub_rand - 1`
   - Use the commitment for subsequent verification steps

5. **Finality Signature Verification**:
   - Verify `height == pr_commit.start_height + proof.index`
   - Verify `proof.total == pr_commit.num_pub_rand`
   - Verify the inclusion proof for the public randomness value against `pr_commit.commitment`
   - Verify the EOTS signature using:
     - Message: `SHA256(height || block_hash)`
     - Public randomness value and EOTS signature

6. **Equivocation Detection and Handling**: Check if the finality provider has already voted for a different block at this height:
   - Query blocks using key `(height, fp_pubkey_hex)`
   - If exists and differs from current `block_hash_hex`:
     - Extract the secret key using EOTS from the two different signatures
     - Create `Evidence` struct with both signatures and block hashes
     - Save evidence to the contract state using key `(height, fp_pubkey_hex)`
     - Send `BabylonMsg::EquivocationEvidence` to trigger slashing on Babylon Genesis
     - Emit appropriate event indicating equivocation detection

7. **Storage Operations**: Store the finality signature and related data:
   - Save signature to the contract state using key `(height, fp_pubkey_hex)`
   - Save block hash (decoded from hex) to the contract state using key `(height, fp_pubkey_hex)`
   - Save public randomness value to the contract state using key `(fp_pubkey_hex, height)`
   - Update the blocks storage:
     - Get existing voters for key `(height, block_hash_bytes)` or create empty HashSet
     - Add `fp_pubkey_hex` to the HashSet
     - Save updated HashSet back to the contract state

#### 5.4.3. Slashing (MUST)

**Message Structure:**
```rust
Slashing {
    sender: Addr,
    evidence: Evidence,
}
```

**Expected Behavior:** Finality contracts MUST implement this handler for manual slashing with the following verification logic:

1. **Admin Authorization**: Verify that the caller is authorized:
   - Query the current admin address
   - Verify that `sender` parameter matches the admin address

2. **Evidence Processing**: Process the provided equivocation evidence:
   - Validate that the `evidence` parameter contains all required fields
   - Verify the evidence cryptographically if needed

3. **Storage Operations**: Store the slashing evidence:
   - Save the `evidence` to the contract state using key `(evidence.block_height, evidence.fp_btc_pk_hex)`

4. **Babylon Message**: Send `BabylonMsg::EquivocationEvidence` to the Babylon chain with:
   - Finality provider BTC public key from evidence
   - Block height of equivocation from evidence
   - Public randomness value from evidence
   - Canonical and fork block hashes from evidence
   - Canonical and fork finality signatures from evidence

#### 5.4.4. SetEnabled (SHOULD)

**Message Structure:**
```rust
SetEnabled {
    enabled: bool,
}
```

**Expected Behavior:** Finality contracts SHOULD implement this administrative handler with the following verification logic:

1. **Admin Authorization**: Verify that the caller is the contract admin:
   - Query `ADMIN` state to get the current admin address
   - Verify that the message sender matches the admin address

2. **State Check**: Verify that the current enabled state differs from the requested state:
   - Query current value from the contract state
   - Compare with the `enabled` parameter
   - Reject if values are identical (no change needed)

3. **Storage Operations**: Update the enabled flag:
   - Save the `enabled` parameter value to the contract state
   - Emit appropriate event indicating the state change

#### 5.4.5. UpdateAdmin (SHOULD)

**Message Structure:**
```rust
UpdateAdmin {
    admin: String,
}
```

**Expected Behavior:** Finality contracts SHOULD implement this administrative handler with the following verification logic:

1. **Admin Authorization**: Verify that the caller is the current contract admin:
   - Query the current admin address
   - Verify that the message sender matches the current admin address

2. **Admin Validation**: Validate the new admin address:
   - Ensure the `admin` parameter is a valid address format
   - Optionally ensure the new admin differs from the current admin

3. **Storage Operations**: Update the admin address:
   - Update the admin address
   - The new admin address from `admin` parameter replaces the current admin
   - Emit appropriate event indicating the admin change

### 5.5. Contract State Storage

This section documents the actual state storage structure used by the finality contract implementation.

#### 5.5.1. Core Configuration

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
      pub consumer_id: String,
  }
  ```

**IS_ENABLED**: Finality gadget enabled status
- Type: `Item<bool>`
- Storage key: `"is_enabled"`
- Purpose: Controls whether the finality gadget is active

#### 5.5.2. Finality State Storage

**FINALITY_SIGNATURES**: Finality signatures by height and provider
- Type: `Map<(u64, &str), FinalitySigInfo>`
- Storage key: `"finality_signatures"`
- Key format: `(block_height, fp_pubkey_hex)`
- Purpose: Stores finality signature information including signature and block hash
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
- Purpose: Maps each (height, block_hash) combination to the set of finality provider public keys that voted for it

#### 5.5.3. Equivocation Evidence State Storage

**EVIDENCES**: Slashing evidence by height and provider
- Type: `Map<(u64, &str), Evidence>`
- Storage key: `"evidences"`
- Key format: `(block_height, fp_pubkey_hex)`
- Purpose: Stores equivocation evidence for slashed finality providers. Each (block_height, fp_pubkey_hex) pair can have at most one evidence entry; evidence is immutable once set.
- Insertion: Use the `set_evidence` helper, which will return an `EvidenceAlreadyExists(fp_pubkey_hex, block_height)` error if evidence already exists for the same key. This prevents accidental overwrites and ensures idempotency.
- Retrieval: Use the `get_evidence` helper to fetch evidence for a given (block_height, fp_pubkey_hex) pair. Returns `None` if not present.
- Structure:
  ```rust
  pub struct Evidence {
      pub fp_btc_pk: Vec<u8>,           // BTC PK of the finality provider
      pub block_height: u64,            // Height of the conflicting blocks
      pub pub_rand: Vec<u8>,            // Public randomness committed to
      pub canonical_app_hash: Vec<u8>,  // AppHash of the canonical block
      pub fork_app_hash: Vec<u8>,       // AppHash of the fork block
      pub canonical_finality_sig: Vec<u8>, // EOTS signature for canonical block
      pub fork_finality_sig: Vec<u8>,       // EOTS signature for fork block
  }
  ```

#### 5.5.4. Public Randomness Storage

**PUB_RAND_VALUES**: Individual public randomness values
- Type: `Map<(&str, u64), Vec<u8>>`
- Storage key: `"pub_rand_values"`
- Key format: `(fp_pubkey_hex, block_height)`
- Purpose: Stores individual public randomness values revealed during finality signature submission

**PUB_RAND_COMMITS**: Public randomness commitments
- Type: `Map<(&str, u64), PubRandCommit>`
- Storage key: `"fp_pub_rand_commit"`
- Key format: `(fp_pubkey_hex, start_height)`
- Structure:
  ```rust
  pub struct PubRandCommit {
    /// The height of the first commitment
    pub start_height: u64,
    /// The amount of committed public randomness
    pub num_pub_rand: u64,
    /// The epoch number of Babylon when the commit was submitted
    pub epoch: u64,
    /// Value of the commitment.
    /// Currently, it's the root of the Merkle tree constructed by the public randomness
    pub commitment: Bytes,
  }
  ```

### 5.6. Finality contract queries

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

    // SHOULD: Administrative queries
    #[returns(AdminResponse)]
    Admin {},
    #[returns(Config)]
    Config {},
    #[returns(bool)]
    IsEnabled {},
}
```

#### 5.6.1. BlockVoters (MUST)

**Query Structure:**
```rust
BlockVoters {
    height: u64,         // Block height to query voters for
    hash_hex: String     // Block hash in hex format
}
```

**Return Type:** `Option<Vec<BlockVoterInfo>>` - List of finality providers and their signatures for the specified block

**Expected Behavior:** Finality contracts MUST implement this query to return
the finality providers that voted for a specific block along with their complete signature information:

1. Decode hash_hex from hex string to bytes
   - IF decode fails: RETURN error

2. Query signatories storage using key (height, hash_bytes)
   - Access the stored set of finality provider public keys

3. For each finality provider in the set:
   - Query the FINALITY_SIGNATURES storage using key (height, fp_pubkey_hex)
   - IF signature not found: RETURN error (state corruption)
   - Query the PUB_RAND_VALUES storage using key (fp_pubkey_hex, height)
   - IF public randomness not found: RETURN error (state corruption)
   - Create BlockVoterInfo with fp_btc_pk_hex, pub_rand, and FinalitySigInfo

4. Return the list of BlockVoterInfo
   - IF no votes found: RETURN `None`
   - IF votes exist: RETURN `Some(Vec<BlockVoterInfo>)`

WHERE BlockVoterInfo contains:
- `fp_btc_pk_hex`: `String` - The finality provider's BTC public key in hex format
- `pub_rand`: `Vec<u8>` - The public randomness value for the block
- `finality_signature`: `FinalitySigInfo` - Complete signature information including public randomness, signature, and block hash

#### 5.6.2. FirstPubRandCommit (MUST)

**Query Structure:**
```rust
FirstPubRandCommit {
    btc_pk_hex: String    // BTC public key of the finality provider in hex format
}
```

**Return Type:** `Option<PubRandCommit>` - The first public randomness
commitment or None if not found

**Expected Behavior:** Finality contracts MUST implement this query to return
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
- `fp_btc_pk_hex`: `String`
- `num_pub_rand`: `u64`  
- `commitment`: `Binary`
- `signature`: `Binary`

#### 5.6.3. LastPubRandCommit (MUST)

**Query Structure:**
```rust
LastPubRandCommit {
    btc_pk_hex: String    // BTC public key of the finality provider in hex format
}
```

**Return Type:** `Option<PubRandCommit>` - The last public randomness commitment
or `None` if not found

**Expected Behavior:** Finality contracts MUST implement this query to return
the last public randomness commitment for a given finality provider:

1. Query public randomness commitments storage with prefix btc_pk_hex
   - Search for all commitments belonging to this finality provider

2. Sort commitments by start_height in descending order
   - Find the commitment with the highest start_height

3. Return the last commitment
   - IF no commitments found: RETURN `None`
   - IF commitments exist: RETURN `Some(last_commitment)`
   
WHERE PubRandCommit contains:
- `fp_btc_pk_hex`: `String`
- `start_height`: `u64`
- `num_pub_rand`: `u64`  
- `commitment`: `Binary`
- `signature`: `Binary`

#### 5.6.4. Admin (SHOULD)

**Query Structure:**
```rust
Admin {}    // No parameters required
```

**Return Type:** `AdminResponse` - Contains the current admin address

**Expected Behavior:** Finality contracts SHOULD implement this administrative
query to return the current admin address:

1. Query admin storage to retrieve current admin address
   - Access the stored admin address value

2. Return admin information
   - Return AdminResponse containing the admin address
   - IF no admin set: RETURN `None`
   
WHERE AdminResponse contains:
- `admin`: `Option<String>`

#### 5.6.5. Config (SHOULD)

**Query Structure:**
```rust
Config {}    // No parameters required
```

**Return Type:** `Config` - Contract configuration settings

**Expected Behavior:** Finality contracts SHOULD implement this administrative
query to return the contract configuration:

1. Query configuration storage to retrieve current settings
   - Access all stored configuration parameters

2. Return configuration information
   - Return Config struct with all configuration values
   - All configuration fields should be populated
   
WHERE Config contains:
- `consumer_id`: `String` - The consumer chain identifier for this finality contract

#### 5.6.6. IsEnabled (SHOULD)

**Query Structure:**
```rust
IsEnabled {}    // No parameters required
```

**Return Type:** `bool` - Whether the finality contract is enabled

**Expected Behavior:** Finality contracts SHOULD implement this administrative
query to return whether the finality gadget is enabled:

1. Query enabled status storage to retrieve current state
   - Access the stored boolean enabled flag

2. Return enabled status
   - Return `true` if finality contract is enabled
   - Return `false` if finality contract is disabled

## 6. Implementation status

### 6.1. Babylon implementation status

The interfaces in this specification have been fully implemented in the [Babylon codebase](https://github.com/babylonlabs-io/babylon) (`main` branch). This includes all required message types, queries, and expected behaviors for finality contract integration.

### 6.2. Finality contracct implementation status

As of this writing, there are two known implementations of finality contracts
that integrate with Babylon's Bitcoin staking protocol:

1. **OP Finality Gadget** - Available at
   [babylonlabs-io/rollup-bsn-contracts](https://github.com/babylonlabs-io/rollup-bsn-contracts).
   This implementation is a CosmWasm smart contract designed to integrate OP
   Stack rollups with Babylon's Bitcoin staking protocol. The contract is
   actively developed and maintained by Babylon Labs.

2. **BLITZ** - Available at
   [alt-research/blitz](https://github.com/alt-research/blitz). This
   implementation provides fast finality for Arbitrum Orbit chains using
   Babylon's Bitcoin staking protocol. BLITZ includes both the finality contract
   (`nitro-finality-gadget`) and supporting infrastructure for Arbitrum Orbit
   integration. The project is developed and maintained by AltLayer.

**Comparison**: While both implementations follow the general principles
outlined in this specification, they target different rollup architectures. The OP
Finality Gadget is specifically designed for OP Stack chains and leverages
CosmWasm for deployment on Babylon, whereas BLITZ focuses on Arbitrum Orbit
chains and includes additional infrastructure components for the Nitro-based
architecture.

<!-- TODO: add Manta contract after open-source -->
