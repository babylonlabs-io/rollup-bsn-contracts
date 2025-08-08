# Contract Migration Guide

This guide explains how to safely migrate the Rollup BSN Contract to new
versions in production environments.

## Overview

The Rollup BSN Contract supports migration through CosmWasm's built-in migration
mechanism. This allows you to upgrade the contract's logic while preserving its
state and address, which is essential for production deployments where you need
to add new features or fix bugs without disrupting existing functionality.

## How CosmWasm Migration Works

Understanding the migration process is crucial for successful upgrades:

1. **The `migrate` entry point runs on the NEW code** - When you call `babylond
   tx wasm migrate`, the blockchain loads the new contract code and executes its
   `migrate` function against the existing state of the contract address.

2. **Migration requirements**:
   - The new code you are migrating to must export a `migrate` entry point
   - If the new code has no `migrate` export, migration fails with: `"Missing
     export: migrate"`
   - **Only the contract admin can execute migrations** - this is enforced by
     the CosmWasm runtime
   - The contract must have been instantiated with an admin (using `--admin`
     flag)

3. **Migration flow**:
   - Store new contract code → get new `code_id`
   - Call migrate with contract address + new `code_id`
   - New code's `migrate` entry point executes and can transform state
   - On success, the contract address now points to the new `code_id`
   - Contract address and storage persist, only the code changes

## Migration Message Format

When executing a migration, you provide a `MigrateMsg` with the following
structure:

```json
{
  "version": "v2.0.0"  // Optional: version string for tracking
}
```

**Parameters:**
- `version` (optional): A version string to track the migration in contract
  events

## Migration Types

### Non-State-Breaking Migrations

These migrations don't change the storage structure and are handled
automatically:

- **Logic improvements**: Bug fixes, performance optimizations
- **New functionality**: Adding new execute/query handlers that don't modify
  existing state
- **Internal changes**: Refactoring that doesn't affect storage layout

**Example**: Adding enhanced validation or new event emissions without changing
stored data structures.

### State-Breaking Migrations

**Currently not supported.** The current migration implementation only handles
non-state-breaking changes. State-breaking migrations that require data
transformation would need additional implementation in the contract's `migrate`
function.

Examples of state-breaking changes that would require future development:
- **Adding fields**: New fields in existing structs
- **Removing fields**: Deprecated fields that need cleanup  
- **Type changes**: Converting field types (e.g., `u32` to `u64`)
- **Storage restructuring**: Changing storage keys or data organization

## Step-by-Step Migration Process

### 1. Build and Store New Contract

```bash
# Build the optimized contract
cargo run-script optimize

# Store the new contract code
STORE_JSON=$(babylond tx wasm store artifacts/finality.wasm \
  --from <admin_key> \
  --chain-id <chain_id> \
  --keyring-backend <keyring_backend> \
  --gas auto --gas-adjustment 1.3 \
  --fees <fee_amount><fee_denom> \
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
  --keyring-backend <keyring_backend> \
  --gas auto --gas-adjustment 1.3 \
  --fees <fee_amount><fee_denom> \
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

The contract includes migration tests:

```bash
# Run migration-specific tests
cargo test test_migrate -p finality

# Run all tests
cargo test -p finality
```

### Integration Testing

For comprehensive testing in production environments:

1. **Test on testnet first**: Always test the complete migration process on
   testnet first
2. **Verify functionality**: Ensure all contract functions work correctly after
   migration  
3. **Check state integrity**: Confirm that all data has been preserved or
   properly transformed

## Troubleshooting

### Common Issues

1. **"Missing export: migrate"**
   - **Cause**: The NEW code you are migrating to does not export a `migrate`
     entry point
   - **Solution**: Rebuild and store code that includes a `migrate` entry point,
     then retry the migration

2. **Migration transaction succeeds but code ID doesn't change**
   - **Cause**: Transaction may not have been included in a block yet
   - **Solution**: Wait longer and re-query, or check transaction events for
     errors

3. **"Permission denied" or admin errors**
   - **Cause**: Wrong account trying to execute migration, or contract has no
     admin set
   - **Solution**: Ensure the contract admin is signing the migration
     transaction. Check the contract admin with: `babylond query wasm contract
     <contract_address>` transaction

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

1. **Always test first**: Test migrations thoroughly on testnet before mainnet
2. **Backup important data**: Ensure you have backups of critical contract state
3. **Monitor after migration**: Check contract health and functionality
   post-migration
4. **Use version tracking**: Include version strings for clear audit trails
5. **Plan for rollbacks**: Have a strategy if migration issues arise
6. **Secure admin keys**: Ensure migration admin keys are properly secured
7. **Document changes**: Keep clear records of all migration steps and changes

## Migration Capabilities

The Rollup BSN Contract currently supports:

- **Non-state-breaking migrations**: Upgrade logic while preserving existing
  data structure
- **Version tracking**: Optional version strings for audit trails  
- **Admin-only execution**: Secure migration process restricted to contract
  admin

**Note**: State-breaking migrations that require data transformation are not
currently implemented and would require additional development.

## Support and Resources

- **CosmWasm documentation**: [Official CosmWasm migration
  guide](https://docs.cosmwasm.com/docs/1.0/smart-contracts/migration)
- **Community support**: Join the Babylon community for migration assistance and
  best practices
- **Testing**: Always test thoroughly on testnet before production migrations