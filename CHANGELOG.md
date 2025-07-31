<!--
Guiding Principles:

Changelogs are for humans, not machines.
There should be an entry for every single version.
The same types of changes should be grouped.
Versions and sections should be linkable.
The latest version comes first.
The release date of each version is displayed.
Mention whether you follow Semantic Versioning.

Usage:

Change log entries are to be added to the Unreleased section under the
appropriate stanza (see below). Each entry should have following format:

* [#PullRequestNumber](PullRequestLink) message

Types of changes (Stanzas):

"Features" for new features.
"Improvements" for changes in existing functionality.
"Deprecated" for soon-to-be removed features.
"Bug Fixes" for any bug fixes.
"Client Breaking" for breaking CLI commands and REST routes used by end-users.
"API Breaking" for breaking exported APIs used by developers building on SDK.
"State Machine Breaking" for any changes that result in a different AppState
given same genesisState and txList.
Ref: https://keepachangelog.com/en/1.0.0/
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## Unreleased

### State and API breaking

* [82](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/82) feat: add
  bsn_activation_height and finality_signature_interval for spam protection
* [97](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/97) feat:
  versioning of FP allowlist

### Improvements

* [#91](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/91) feat:
  optimize public key handling by using bytes instead of hex
* [#98](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/98) feat:
  admin handler to update config

## v0.1.0

### State and API breaking

* [#65](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/65) Remove
  `is_enabled` flag and associated functionality from finality contract
* [#40](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/40)
  Timestamped public randomness commitments. Breaks `PubRandCommit` struct that
  is being used for both storage and queries.

### API breaking

* [#80](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/80) feat:
  rate limiting for FP messages
* [#60](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/60) feat:
  add signing context

### State breaking

* [#73](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/73) Add data
  pruning handler for finality signatures, signatories and public randomness
  values
* [#55](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/55)
  evidence: remove evidence DB
* [#35](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/35) chore:
  use consistent naming for state maps
* [#40](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/40) Refactor
  votes storage.
* [#75](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/75) chore:
  store conflicting finality sigs in storage

### Improvements

* [#95](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/95) docs: rollup contract managment
* [#83](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/83) docs: rollup bsn contract guide
* [#84](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/84) chore: consolidate tests for InstantiateMsg
* [#81](https://github.com/babylonlabs-io/rollup-bsn-contracts/issues/81) Add
  allowlist functionality for finality providers.
* [76](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/76) chore:
  admin unit tests
* [#71](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/71) chore:
  fix signing context
* [#69](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/69) Define
  state setter functions
* [#64](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/64) chore:
  clean up metadata
* [#62](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/62) Add
  consumer ID format validation and admin address validation during contract
  instantiation and admin updates
* [#56](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/56) e2e:
  migrate e2e from babylon to contract repo
* [#57](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/57) Fix
  block voters response type annotation
* [#51](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/51)
  finality: refactor handle_finality_signature and revise unit tests
* [#52](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/52) chore:
  remove unused fields in FP struct.
* [#31](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/31) Rename
  `hash` to `hash_hex`.
* [#42](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/42) test:
  Add unit tests for public randomness commitment validation.
* [#47](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/47) Create
  state/evidence.rs file and define setters/getters.
* [#23](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/23) Clean up
  dependencies to cosmos-bsn-contracts.
* [#24](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/24) Validate
  public randomness commitment.
* [#25](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/25) Improve
  `check_fp_exist` to ensure FP is not slashed.
* [#29](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/29) feat:
  Remove slashing evidence message
* [59](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/59) chore:
  add missing validations in handle_public_randomness_commit
* [70](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/70) chore:
  new query for fetch all pub rand commit
