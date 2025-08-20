# Rollup BSN Contracts

**Bitcoin-secured finality for rollups through Babylon's Bitcoin staking
protocol.**

This repository contains the finality contract that enables Ethereum Rollups to
become Bitcoin Supercharged Networks (BSNs) by inheriting Bitcoin's economic
security through Babylon's staking infrastructure.

## What is Rollup BSN?

**Bitcoin Supercharged Networks (BSNs)** are blockchain networks that leverage
Bitcoin's economic security through Babylon's Bitcoin staking protocol. BSNs
enhance their security by tapping into Bitcoin's massive economic security,
where Bitcoin stakers delegate their BTC to provide cryptographic attestations
for network finality.

### How It Works

1. **Deploy Contract** - Deploy this finality contract on Babylon Genesis chain
2. **Register BSN** - Register your rollup as a Bitcoin Supercharged Network
3. **BTC Delegation** - Bitcoin stakers delegate their BTC to finality providers
4. **Block Finalization** - Finality providers sign rollup blocks and submit
   signatures to the contract
5. **Cross-Chain Security** - Your rollup inherits Bitcoin's economic security
   through Babylon's infrastructure

The finality contract acts as the bridge between your rollup and Babylon's
Bitcoin staking protocol, maintaining an immutable record of block finalization
and ensuring finality providers remain honest through economic incentives.

> **Note:** To read finalized data from contracts on Babylon Genesis, you should
> use an already built off-chain service or build your own. We have a
> proof-of-concept available at
> [rollup-finality-gadget](https://github.com/babylonlabs-io/rollup-finality-gadget).

### Security Through Cryptography

The system uses **EOTS (Extractable One-Time Signatures)** to ensure finality
provider honesty:

- **Public Randomness Commitment** - Finality providers pre-commit to randomness
  values they'll use for signing
- **Block Finality Signatures** - Finality providers sign rollup block data
  using their private keys
- **One-Time Signatures** - Each signature uses unique randomness and can only
  be used once safely
- **Automatic Slashing** - If a provider signs two different blocks at the same
  height (double-signing), the contract automatically extracts their private key
  and triggers slashing

## Repository Structure

- **`contracts/finality/`** - Core finality contract implementing BSN
  integration
- **`docs/`** - Comprehensive technical specifications and guides
- **`e2e/`** - End-to-end integration tests
- **`scripts/`** - Development and deployment utilities

## Quick Start

### Prerequisites

```bash
# Install dependencies
cargo install cargo-run-script
```

### Build & Test

```bash
# Build the contract
cargo build

# Run tests
cargo test --lib

# Build optimized version for deployment
cargo run-script optimize
```

### Deploy to Babylon

1. **Upload Contract**: Deploy WASM bytecode to Babylon Genesis
2. **Instantiate**: Configure your BSN parameters
3. **Register BSN**: Register with Babylon's consumer registry
4. **Go Live**: Start accepting finality signatures from Finality Providers

See our [Contract Management Guide](docs/contract-managment.md) for detailed
deployment instructions.

## Development Commands

```bash
# Linting & formatting
cargo run-script lint

# Integration tests (requires optimized build)
cargo run-script integration

# End-to-end tests
cargo run-script e2e

# Generate contract schema
cargo run-script schema
```

## Contributing

We welcome contributions! This project follows the same guidelines as the
[Babylon node repository](https://github.com/babylonlabs-io/babylon/blob/main/CONTRIBUTING.md).

---

**Need Help?** Check our [documentation](docs/) or open an issue for support.

**Learn More:** Visit [Babylon Labs](https://babylonlabs.io) to understand the
broader Bitcoin staking ecosystem.