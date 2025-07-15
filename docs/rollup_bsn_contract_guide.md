# Rollup BSN Contract Guide

## Introduction

The Rollup BSN contract is a CosmWasm smart contract deployed on the Babylon Genesis
chain that tracks finality signatures for rollup blocks. It verifies who signed,
detects double-signing, and reports misbehavior for slashing. This is the core and only
contract that a rollup needs to deploy to become a BSN. The contract must be deployed
on Babylon Genesis because it relies on Babylon-specific modules and state.