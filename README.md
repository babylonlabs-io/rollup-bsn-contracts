# Op-finality-gadget

This repo contains the Wasm smart contract for Optimism staking integration.
It will be deployed on Babylon, and will maintain finality signatures and block finalisation status of Optimism rollups.

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

### Test the contract

Note: Requires the optimized contract to be built (`cargo optimize`)

Runs all the CI checks locally (in your actual toolchain).

```bash
cargo test --lib
```

### Integration tests the contract

Note: Requires the optimized contract to be built (`cargo optimize`)

```bash
cargo test --test integration
```

Alternatively, you can run the following command, that makes sure to build the optimized contract before running
the integration tests.

```bash
cargo run-script integration
```

### Build the optimized contract

```bash
cargo run-script optimize
```
