# Finality contract specification for the rollup integration

- [Finality contract specification for the rollup integration](#finality-contract-specification-for-the-rollup-integration)
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
    - [5.3. Finality Contract message handlers](#53-finality-contract-message-handlers)
      - [5.3.1. CommitPublicRandomness (MUST)](#531-commitpublicrandomness-must)
      - [5.3.2. SubmitFinalitySignature (MUST)](#532-submitfinalitysignature-must)
      - [5.3.3. Slashing (MUST)](#533-slashing-must)
      - [5.3.4. SetEnabled (SHOULD)](#534-setenabled-should)
      - [5.3.5. UpdateAdmin (SHOULD)](#535-updateadmin-should)
    - [5.4. Finality contract queries](#54-finality-contract-queries)
      - [5.4.1. BlockVoters (MUST)](#541-blockvoters-must)
      - [5.4.2. FirstPubRandCommit (MUST)](#542-firstpubrandcommit-must)
      - [5.4.3. LastPubRandCommit (MUST)](#543-lastpubrandcommit-must)
      - [5.4.4. Admin (SHOULD)](#544-admin-should)
      - [5.4.5. Config (SHOULD)](#545-config-should)
      - [5.4.6. IsEnabled (SHOULD)](#546-isenabled-should)
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
use babylon_bindings::BabylonMsg;

// Interface provided by Babylon Genesis chain
BabylonMsg::EquivocationEvidence {
    /// Address of the entity reporting the equivocation
    signer: String,
    /// BTC public key of the equivocating finality provider
    fp_btc_pk: Vec<u8>,
    /// Block height at which an equivocation occurred
    block_height: u64,
    /// Public randomness value used in both signatures
    pub_rand: Vec<u8>,
    /// Application hash of the canonical block
    canonical_app_hash: Vec<u8>,
    /// Application hash of the fork block
    fork_app_hash: Vec<u8>,
    /// EOTS signature on the canonical block
    canonical_finality_sig: Vec<u8>,
    /// EOTS signature on the fork block
    fork_finality_sig: Vec<u8>,
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

#### 5.2.1. QueryFinalityProvider (MUST)

Currently, the finality contract only utilizes the
`/babylon.btcstkconsumer.v1.Query/FinalityProvider` endpoint (implemented in
[Babylon](https://github.com/babylonlabs-io/babylon/blob/main/x/btcstaking/keeper/grpc_query.go))
to query finality provider information. The request and response types are
defined as follows:
<!-- TODO: use a release rather than a commit for the pointer -->

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

The finality contract MAY interface with the Cosmos SDK layer through CosmWasm's
`query_grpc` method. The request and response structs in Rust MUST match the
protobuf messages, in that each field MUST use the same name, type and tag
number as in protobuf.

### 5.3. Finality Contract message handlers

The finality contract message requirements are divided into core finality
functionality (MUST) and administrative functionality (SHOULD):

```rust
use babylon_apis::finality_api::Evidence;
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
    /// The signature is verified by the Consumer chain using the finality provider's public key
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
        app_block_hash: Binary,
        /// Finality signature on (height || app_block_hash) signed by finality provider
        signature: Binary,
    },
    /// Slashing message.
    ///
    /// This message slashs a finality provider for misbehavior.
    /// The caller must provide evidence of the misbehavior in the form of an Evidence struct.
    /// If the evidence is valid, the finality contract will send the evidence to the Babylon
    /// Genesis chain for actual slashing.
    Slashing {
        sender: Addr,
        evidence: Evidence,
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

#### 5.3.1. CommitPublicRandomness (MUST)

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

#### 5.3.2. SubmitFinalitySignature (MUST)

**Message Structure:**
```rust
SubmitFinalitySignature {
    fp_pubkey_hex: String,
    height: u64,
    pub_rand: Binary,
    proof: Proof,
    app_block_hash: Binary,
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
   - If both exist and match the provided `app_block_hash` and `signature`, reject as duplicate

4. **Public Randomness Commitment Retrieval**: Find the public randomness commitment that covers the target height:
   - Query public randomness commitment state to find commitment where `start_height <= height <= start_height + num_pub_rand - 1`
   - Use the commitment for subsequent verification steps

5. **Finality Signature Verification**:
   - Verify `height == pr_commit.start_height + proof.index`
   - Verify `proof.total == pr_commit.num_pub_rand`
   - Verify the inclusion proof for the public randomness value against `pr_commit.commitment`
   - Verify the EOTS signature using:
     - Message: `SHA256(height || app_block_hash)`
     - Public randomness value and EOTS signature

6. **Equivocation Detection**: Check if the finality provider has already voted for a different block at this height:
   - Query blocks using key `(height, fp_pubkey_hex)`
   - If exists and differs from current `app_block_hash`:
     - Extract the secret key using EOTS from the two different signatures
     - Create `Evidence` struct with both signatures and block hashes
     - Save evidence to the contract state using key `(height, fp_pubkey_hex)`
     - Send `BabylonMsg::EquivocationEvidence` to trigger slashing

7. **Storage Operations**: Store the finality signature and related data:
   - Save signature to the contract state using key `(height, fp_pubkey_hex)`
   - Save block hash to the contract state using key `(height, fp_pubkey_hex)`
   - Save public randomness value to the contract state using key `(fp_pubkey_hex, height)`
   - Update the blocks storage:
     - Get existing voters for key `(height, app_block_hash_bytes)` or create empty HashSet
     - Add `fp_pubkey_hex` to the HashSet
     - Save updated HashSet back to the contract state

#### 5.3.3. Slashing (MUST)

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

#### 5.3.4. SetEnabled (SHOULD)

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

#### 5.3.5. UpdateAdmin (SHOULD)

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

### 5.4. Finality contract queries

The finality contract query requirements are divided into core finality
functionality (MUST) and administrative functionality (SHOULD):

```rust
use cosmwasm_schema::{cw_serde, QueryResponses};
use babylon_apis::finality_api::PubRandCommit;
use cw_controllers::AdminResponse;
use std::collections::HashSet;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {    
    // MUST: Core finality queries
    #[returns(Option<HashSet<String>>)]
    BlockVoters { height: u64, hash: String },
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

#### 5.4.1. BlockVoters (MUST)

**Query Structure:**
```rust
BlockVoters {
    height: u64,      // Block height to query voters for
    hash: String      // Block hash in hex format
}
```

**Return Type:** `Option<HashSet<String>>` - Set of finality provider BTC public
keys in hex format

**Expected Behavior:** Finality contracts MUST implement this query to return
the set of finality providers that voted for a specific block:

1. Decode hash from hex string to bytes
   - IF decode fails: RETURN error

2. Query block votes storage using key (height, hash_bytes)
   - Access the stored set of finality provider public keys

3. Return the set of finality provider BTC public keys (hex format)
   - IF no votes found: RETURN `None`
   - IF votes exist: RETURN `Some(HashSet of fp_pubkey_hex strings)`

#### 5.4.2. FirstPubRandCommit (MUST)

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

#### 5.4.3. LastPubRandCommit (MUST)

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

#### 5.4.4. Admin (SHOULD)

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

#### 5.4.5. Config (SHOULD)

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
   
WHERE Config contains implementation-specific fields such as:
- `consumer_id`: `String`         
- `babylon_tag`: `String`         
- `btc_confirmation_depth`: `u32` 
- `checkpoint_finalization_timeout`: `u64` 
- other implementation-specific parameters

#### 5.4.6. IsEnabled (SHOULD)

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
