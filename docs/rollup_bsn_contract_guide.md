# Rollup BSN Contract Guide

## Introduction

The Rollup BSN contract runs on Babylon Genesis and tracks finality signatures for rollup blocks. It verifies who signed, detects double-signing, and reports misbehavior for slashing. This is the core contract rollups use to connect to Babylon’s Bitcoin staking protocol.

## Why Deploy on Babylon

The Rollup BSN contract must be deployed on the Babylon Genesis chain. It depends on features that only exist in the Babylon environment. This information cannot be easily bridged to the consumer BSN, unlike Cosmos-to-Cosmos IBC setups.

Key dependencies include:
- **Finality Provider Queries**: [implementation](../contracts/finality/src/utils.rs#L21-L44) - Used to verify that FPs are registered, active, and linked to the correct BSN

- **Slashing and Key Extraction**: [implementation](../contracts/finality/src/exec/finality.rs#L85-L95) - Equivocation evidence is submitted to Babylon, which handles slashing and secret key extraction using EOTS

- **Epoch-Based Timestamping**: [implementation](../contracts/finality/src/custom_queries.rs#L7-L19) - Ensures that public randomness commitments are timestamped to Bitcoin using Babylon's native epoch system
