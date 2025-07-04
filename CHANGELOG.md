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

### State breaking

* [#35](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/35) chore: use consistent naming for state maps
* [#40](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/40) Refactor votes storage.

### Improvements

* [#52](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/52) chore: remove unused fields in FP struct.
* [#31](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/31) Rename `hash` to `hash_hex`.
* [#42](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/42) test: Add unit tests for public randomness commitment validation.
* [#47](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/47) Create state/evidence.rs file and define setters/getters.
* [#23](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/23) Clean up dependencies to cosmos-bsn-contracts.
* [#24](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/24) Validate public randomness commitment.
* [#25](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/25) Improve `check_fp_exist` to ensure FP is not slashed.
* [#29](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/29) feat: Remove slashing evidence message
