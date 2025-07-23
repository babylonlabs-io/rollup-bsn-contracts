# Rollup BSN Contract – Configuration Specification

## Overview
This document defines the parameters accepted during instantiation
of the Rollup BSN contract. Each parameter is described in terms of
its role within the system, expected format, and configuration considerations.
These values are set once at deployment and directly influence the contract’s behavior and validation rules.

To learn how to instantiate the contract, see the [deployment guide](./deployment-integration.md)

### Instantiation Parameters

The following parameters must be provided when deploying the Rollup BSN
contract:

- `admin`: Babylon Genesis address of the contract administrator
- `bsn_id`: Unique identifier for the BSN rollup
- `allowed_finality_providers`: List of BTC public keys authorized to submit
  finality signatures and randomness
- `bsn_activation_height`: Rollup block height at which finality becomes
  active
- `finality_signature_interval`: Interval (in rollup blocks) that determines
  which blocks are eligible for finality signatures
- `min_pub_rand`: Minimum number of public randomness values submitted per
  commit
- `rate_limiting_interval`: Block interval used to enforce rate limiting on
  finality provider messages
- `max_msgs_per_interval`: Maximum number of messages a finality provider can
  submit within a rate limiting interval

The section below defines each parameter in detail. It includes the expected
format, its purpose within the system, and configuration considerations.

---

#### `admin`

The Babylon address with administrative control over the contract.

This address is authorized to perform privileged actions such as modifying the
allow-list, pausing the contract, or executing other administrative operations.
It is critical to secure this key and assign it to a trusted entity.

The admin address can be updated after deployment using the following message:

**Type**: `String` (Bech32 Babylon address)  
**Required**: Yes
**Mutable**: Yes (via `update_admin` message)

---

#### `bsn_id`

A unique identifier for the BSN rollup.

This value is used to associate finality signatures and public randomness
submissions with a specific BSN instance. It also determines how the rollup is tracked on the Babylon chain. Each `bsn_id` must be globally unique.

**Type**: `String` 
**Required**: Yes 
**Mutable**: No 

---

#### `allowed_finality_providers`

List of BTC public keys that are authorized to submit finality signatures and
public randomness to the contract.

Each entry in the list must be a hex-encoded compressed BTC public key. Only
keys included in this list will be permitted to submit data. Messages from
unauthorized keys will be rejected by the contract.

This parameter defines the initial allow-list at deployment time. It can be
modified after instantiation by the contract admin.

To learn how to configure and manage the allow-list see the [allow-list guide](./ALLOW-LIST.md)

**Type**: `Array[String]` (Hex-encoded compressed BTC public keys) 
**Required**: No (default [])
**Mutable**: Yes (via `add_to_allowlist` and `remove_from_allowlist` messages)

---

#### `bsn_activation_height`

The rollup block height at which finality tracking begins.

Submissions for blocks below this height will be rejected. This parameter
ensures that Finality Providers only attest to blocks produced after the BSN is
considered active.

**Type**: `Integer` (positive)  
**Required**: Yes 
**Mutable**: No

---

#### `finality_signature_interval`

Defines how often Finality Providers are expected to submit finality signatures.

Only rollup blocks where  
`(height - bsn_activation_height) % finality_signature_interval == 0`  
are considered valid targets for submission. All other submissions will be
rejected.

This parameter controls the granularity of finality and can be tuned based on
the rollup's expected block frequency and finality requirements.

**Type**: `Integer` (positive)  
**Required**: Yes 
**Mutable**: No

---

#### `min_pub_rand`

Specifies the minimum number of public randomness values required in each
submission.

Finality Providers must include at least this number of randomness values when
committing public randomness. Submissions with fewer values will be rejected by
the contract.

This parameter helps ensure sufficient entropy is provided during each commit.

**Type**: `Integer` (positive)  
**Required**: Yes 
**Mutable**: No

---

#### `rate_limiting_interval`

Specifies the length of the rate-limiting window, measured in Babylon blocks.

Each Finality Provider is allowed to submit up to a fixed number of messages
within this interval, as defined by `max_msgs_per_interval`. Once the interval
resets, the provider's submission count is cleared.

This parameter helps prevent spam or accidental flooding by limiting how often
a provider can interact with the contract over time.

**Type**: `Integer` (positive)  
**Required**: Yes 
**Mutable**: No

---

#### `max_msgs_per_interval`

Defines the maximum number of messages a Finality Provider can submit within a
single rate-limiting interval.

This includes all valid message types handled by the contract, such as finality
signatures and public randomness submissions. Once a provider reaches this
limit, any further messages during the current interval will be rejected.

This parameter works together with `rate_limiting_interval` to control the
submission rate and protect the contract from overload.

**Type**: `Integer` (positive) 
**Required**: Yes  
**Mutable**: No
