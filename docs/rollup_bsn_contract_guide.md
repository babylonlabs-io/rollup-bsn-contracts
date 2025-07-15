# Rollup BSN Contract Guide

## Introduction

The Rollup BSN contract runs on Babylon Genesis and tracks finality signatures for rollup blocks. It verifies who signed, detects double-signing, and reports misbehavior for slashing. This is the core contract rollups use to connect to Babylon’s Bitcoin staking protocol.

## Why Deploy on Babylon

The Rollup BSN contract must be deployed on the Babylon Genesis chain. It depends on features that only exist in the Babylon environment. This information cannot be easily bridged to the consumer BSN, unlike Cosmos-to-Cosmos IBC setups.

Key dependencies include:
- **Finality Provider Queries**: [implementation](../contracts/finality/src/utils.rs#L21-L44) - Used to verify that FPs are registered, active, and linked to the correct BSN

- **Slashing and Key Extraction**: [implementation](../contracts/finality/src/exec/finality.rs#L85-L95) - Equivocation evidence is submitted to Babylon, which handles slashing and secret key extraction using EOTS

- **Epoch-Based Timestamping**: [implementation](../contracts/finality/src/custom_queries.rs#L7-L19) - Ensures that public randomness commitments are timestamped to Bitcoin using Babylon's native epoch system

## Core Features

The Rollup BSN contract handles all finality-related logic for rollup blocks. It tracks votes, enforces rules around randomness, and ensures misbehavior is punished. Below are the key features it provides:

- **Signature Storage**: [implementation](../contracts/finality/src/state/finality.rs#L109-L115) – Stores all finality signatures submitted for each rollup block height

- **Vote Tracking**: [implementation](../contracts/finality/src/state/finality.rs#L10-L11) – Tracks which finality providers signed which blocks, which later can be obtained to check quorum

- **Equivocation Detection**: [implementation](../contracts/finality/src/exec/finality.rs#L85-L95) – Detects when a provider signs conflicting blocks at the same height and builds cryptographic evidence.

- **Randomness Commitments**: [implementation](../contracts/finality/src/exec/public_randomness.rs#L15) – Enforces commit-reveal process where providers pre-commit randomness before signing.

- **Query Interfaces**: [implementation](../contracts/finality/src/queries.rs#L17) – Exposes endpoints to query voter sets, randomness commitments, and block-level signature data.

- **Admin Controls**: [implementation](../contracts/finality/src/contract.rs#L124-L130) – Supports config changes and data pruning

