# Contract Migration Guide

This document explains how to migrate the Rollup BSN Contract to new versions while preserving state and contract address.

## Overview

The Rollup BSN Contract supports migration through CosmWasm's built-in migration mechanism. This allows you to upgrade the contract's logic while preserving its state and address, which is essential for production deployments where you need to add new features or fix bugs without disrupting existing functionality.

## How CosmWasm Migration Works

Understanding the migration process is crucial for successful upgrades:

1. **The `migrate` entry point runs on the OLD contract** - When you call `babylond tx wasm migrate`, the migration function from the currently deployed contract (old code) is executed, not the new contract.

2. **Migration requirements**:
   - The old contract must have exported a `migrate` entry point at deployment time
   - If the old contract has no `migrate` export, migration fails with: `"Missing export migrate"`
   - Only the contract admin can execute migrations

3. **Migration flow**:
   - Store new contract code → get new `code_id`
   - Call migrate with contract address + new `code_id`
   - Old contract's `migrate` function executes and can transform state
   - On success, the contract address now points to the new `code_id`
   - Contract address and storage persist, only the code changes

## Migration Implementation

### Current Implementation

The contract includes a basic migration handler in `src/contract.rs`:

```rust
/// Handle contract migration.
/// This function is called when the contract is migrated to a new version.
/// For non-state-breaking migrations, this is a simple no-op.
pub fn migrate(
    _deps: DepsMut<BabylonQuery>,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    // For non-state-breaking migration, just log the migration
    let mut response = Response::new().add_attribute("action", "migrate");

    if let Some(version) = msg.version {
        response = response.add_attribute("version", version);
    }

    Ok(response)
}
```

### MigrateMsg Structure

The migration message is defined in `src/msg.rs`:

```rust
/// Migration message for contract upgrades.
/// This can be extended in the future to include migration-specific parameters.
#[cw_serde]
pub struct MigrateMsg {
    /// Optional version string for tracking migration
    pub version: Option<String>,
}
```

## Migration Types

### Non-State-Breaking Migrations

These migrations don't change the storage structure and are handled by the current implementation:

- **Logic improvements**: Bug fixes, performance optimizations
- **New functionality**: Adding new execute/query handlers that don't modify existing state
- **Internal changes**: Refactoring that doesn't affect storage layout

**Example**: Adding enhanced validation or new event emissions without changing stored data structures.

### State-Breaking Migrations

These migrations require custom logic to transform existing state:

- **Adding fields**: New fields in existing structs
- **Removing fields**: Deprecated fields that need cleanup
- **Type changes**: Converting field types (e.g., `u32` to `u64`)
- **Storage restructuring**: Changing storage keys or data organization

**Example implementation for adding fields**:

```rust
pub fn migrate(
    deps: DepsMut<BabylonQuery>,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Load existing config
    let old_config: ConfigV1 = CONFIG.load(deps.storage)?;
    
    // Transform to new structure with default values for new fields
    let new_config = Config {
        admin: old_config.admin,
        bsn_id: old_config.bsn_id,
        min_pub_rand: old_config.min_pub_rand,
        rate_limiting_interval: old_config.rate_limiting_interval,
        max_msgs_per_interval: old_config.max_msgs_per_interval,
        bsn_activation_height: old_config.bsn_activation_height,
        finality_signature_interval: old_config.finality_signature_interval,
        // New fields with sensible defaults
        max_finality_providers: 100,
        emergency_pause: false,
    };
    
    // Save the transformed config
    CONFIG.save(deps.storage, &new_config)?;
    
    let mut response = Response::new().add_attribute("action", "migrate");
    if let Some(version) = msg.version {
        response = response.add_attribute("version", version);
    }
    
    Ok(response)
}
```

## Step-by-Step Migration Process

### 1. Build and Store New Contract

```bash
# Build the optimized contract
cd rollup-bsn-contracts
cargo run-script optimize

# Store the new contract code
STORE_JSON=$(babylond tx wasm store artifacts/finality.wasm \
  --from <admin_key> \
  --chain-id <chain_id> \
  --keyring-backend test \
  --gas auto --gas-adjustment 1.3 \
  --fees 1000000ubbn \
  --broadcast-mode sync \
  --output json -y)

# Extract transaction hash and wait for inclusion
STORE_TX=$(echo "$STORE_JSON" | jq -r '.txhash')
sleep 10

# Get the new code ID from transaction events
NEW_CODE_ID=$(babylond query tx "$STORE_TX" --output json | \
  jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')

echo "New code ID: $NEW_CODE_ID"
```

### 2. Execute Migration

```bash
# Migrate the existing contract to the new code
babylond tx wasm migrate <contract_address> $NEW_CODE_ID '{"version":"v2.0.0"}' \
  --from <admin_key> \
  --chain-id <chain_id> \
  --keyring-backend test \
  --gas auto --gas-adjustment 1.3 \
  --fees 1000000ubbn \
  --broadcast-mode sync \
  --output json -y
```

### 3. Verify Migration Success

```bash
# Check that the contract now points to the new code ID
babylond query wasm contract <contract_address> --output json | \
  jq -r '.contract_info.code_id'

# Verify the contract is still functional
babylond query wasm contract-state smart <contract_address> '{"config":{}}' \
  --output json
```

**Expected results**:
- Code ID should match the `NEW_CODE_ID` from step 1
- Contract address remains unchanged
- Contract should respond to queries normally

## Testing

### Unit Tests

The contract includes migration tests in `src/contract.rs`:

```bash
# Run migration-specific tests
cargo test test_migrate -p finality

# Run all tests
cargo test -p finality
```

### Integration Testing

For comprehensive testing, use the e2e test environment in the `babylon-bsn-integration-deployment` repository:

```bash
# In babylon-bsn-integration-deployment/deployments/rollup-bsn-demo
make test-migration-complete
```

This will:
1. Deploy an initial contract
2. Store a new version of the contract
3. Execute migration
4. Verify the migration was successful

### Testing State-Breaking Migrations

When implementing state-breaking migrations, create comprehensive tests:

```rust
#[test]
fn test_state_breaking_migration() {
    let mut deps = mock_deps_babylon();
    
    // Store old config format
    let old_config = ConfigV1 { /* old fields */ };
    CONFIG_V1.save(deps.as_mut().storage, &old_config).unwrap();
    
    // Execute migration
    let migrate_msg = MigrateMsg { version: Some("v2.0.0".to_string()) };
    let res = migrate(deps.as_mut(), mock_env(), migrate_msg).unwrap();
    
    // Verify new config format
    let new_config: Config = CONFIG.load(deps.as_ref().storage).unwrap();
    assert_eq!(new_config.admin, old_config.admin);
    // Verify new fields have correct defaults
    assert_eq!(new_config.max_finality_providers, 100);
    assert_eq!(new_config.emergency_pause, false);
}
```

## Troubleshooting

### Common Issues

1. **"Missing export migrate"**
   - **Cause**: The old contract was deployed without migration support
   - **Solution**: Cannot migrate; must deploy a new contract instance

2. **Migration transaction succeeds but code ID doesn't change**
   - **Cause**: Transaction may not have been included in a block yet
   - **Solution**: Wait longer and re-query, or check transaction events for errors

3. **"Permission denied" or admin errors**
   - **Cause**: Wrong account trying to execute migration
   - **Solution**: Ensure the contract admin is signing the migration transaction

4. **State corruption after migration**
   - **Cause**: Incomplete or incorrect state transformation in migrate function
   - **Solution**: Review migration logic, add comprehensive tests

5. **Gas limit exceeded**
   - **Cause**: Complex state migrations require more gas
   - **Solution**: Increase gas limit or break migration into smaller steps

### Debugging Steps

1. **Check transaction status**:
   ```bash
   babylond query tx <transaction_hash> --output json
   ```

2. **Verify contract admin**:
   ```bash
   babylond query wasm contract <contract_address> --output json | jq -r '.contract_info.admin'
   ```

3. **Check migration events**:
   ```bash
   babylond query tx <migration_tx_hash> --output json | jq '.events'
   ```

4. **Test on testnet first**: Always test migrations on a testnet before mainnet

## Best Practices

### Development

1. **Always include migration support**: Deploy every contract version with a `migrate` entry point, even if it's initially a no-op

2. **Version tracking**: Include version information in migration messages and contract state

3. **Backward compatibility**: Design storage structures to be extensible when possible

4. **Migration planning**: Plan state transformations carefully and document breaking changes

### Testing

1. **Comprehensive testing**: Test both successful migrations and failure scenarios

2. **Integration tests**: Use realistic test environments that mirror production

3. **State verification**: Always verify that migrated state is correct and complete

4. **Rollback planning**: Have a strategy for handling failed migrations

### Production

1. **Testnet first**: Always test migrations on testnet before mainnet

2. **Monitoring**: Monitor contract health after migration

3. **Documentation**: Document all migration steps and changes

4. **Admin security**: Ensure migration admin keys are properly secured

## Schema Generation

The contract's migration message is included in the generated schema:

```bash
# Generate updated schema after migration changes
cargo run --bin schema
```

This updates the JSON schema files in `contracts/finality/schema/` including the migration message schema.

## Support and Resources

- **Contract tests**: See `src/contract.rs` for migration test examples
- **CosmWasm docs**: [Official CosmWasm migration guide](https://docs.cosmwasm.com/docs/1.0/smart-contracts/migration)
- **Integration tests**: Check `babylon-bsn-integration-deployment` for e2e migration testing
- **PR reference**: [Migration setup implementation](https://github.com/babylonlabs-io/rollup-bsn-contracts/pull/114)

## Changelog

### Current Implementation (PR #114)
- ✅ Added `MigrateMsg` type with optional version field
- ✅ Implemented basic `migrate` entry point for non-state-breaking migrations
- ✅ Added migration tests (`test_migrate_basic`, `test_migrate_with_version`)
- ✅ Updated schema generation to include migration message
- ✅ Added this migration guide

### Future Enhancements
- [ ] State migration helpers for common patterns
- [ ] Migration validation utilities
- [ ] Automated migration testing framework
- [ ] Migration rollback mechanisms
