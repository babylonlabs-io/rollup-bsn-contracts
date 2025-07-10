# Rollup BSN Contracts

This repo contains the Wasm smart contract for rollup BSN integration. The
contract is intended to be deployed on Babylon Genesis and will maintain
finality signatures and block finalisation status of rollups.

## Specification

For detailed technical specifications and requirements of the finality contract,
please see [SPEC.md](SPEC.md). The spec document outlines the contract's
interfaces, message handlers, queries, and provides guidance for integrators.

## Development

### Prerequisites

Make sure you have `cargo-run-script` installed and docker running.

```bash
cargo install cargo-run-script
```

### Clean the build

```bash
cargo clean
```

### Build the contract

```bash
cargo build
```

### Formatting and Linting

Check whether the code is formatted correctly.

```bash
cargo fmt --all -- --check
cargo check
cargo clippy --all-targets -- -D warnings
```

Alternatively, you can run the following command to run all the checks at once.

```bash
cargo run-script lint
```

### Build the optimized contract

```bash
cargo run-script optimize
```

## Tests

### Unit tests

Note: Requires the optimized contract to be built (`cargo optimize`)

Runs all the CI checks locally (in your actual toolchain).

```bash
cargo test --lib
```

### Integration tests

Note: Requires the optimized contract to be built (`cargo optimize`)

```bash
cargo test --test integration
```

Alternatively, you can run the following command, that makes sure to build the
optimized contract before running the integration tests.

```bash
cargo run-script integration
```

### End-to-End Tests

Note: Requires the optimized contract to be built (`cargo optimize`)

Run the end-to-end tests for the contract.

```bash
cargo run-script e2e
```
