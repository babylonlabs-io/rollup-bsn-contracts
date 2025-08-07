# Contract Migration Guide

This document explains how to migrate the Rollup BSN Contract to new versions.

## Overview

The Rollup BSN Contract supports migration, allowing you to upgrade the
contract's logic while preserving its state and address. This is essential for
production deployments where you need to add new features or fix bugs without
disrupting existing functionality.

## Migration Types

### Non-State-Breaking Migrations

These are migrations that don't change the storage structure:

- Adding new functions
- Changing internal logic
- Bug fixes
- Performance improvements
- Adding new storage keys (unrelated to existing ones)

**Example:**
```rust
// Version 1: Basic functionality
pub fn submit_finality_signature(/* params */) -> Result<Response, ContractError> {
    validate_signature(&signature)?;
    save_signature(&signature)?;
    Ok(Response::new())
}

// Version 2: Enhanced validation
pub fn submit_finality_signature(/* params */) -> Result<Response, ContractError> {
    validate_signature_enhanced(&signature)?; // IMPROVED VALIDATION
    save_signature(&signature)?;
    emit_event(&signature)?; // NEW FEATURE
    Ok(Response::new())
}
```

### State-Breaking Migrations

These are migrations that change the storage structure:

- Adding/removing fields in structs
- Changing field types
- Restructuring data
- Changing storage keys

**Example:**
```rust
// Version 1: Basic config
pub struct Config {
    pub admin: String,
    pub bsn_id: String,
    pub min_pub_rand: u64,
}

// Version 2: Enhanced config
pub struct Config {
    pub admin: String,
    pub bsn_id: String,
    pub min_pub_rand: u64,
    pub max_finality_providers: u32, // NEW FIELD
    pub emergency_pause: bool,        // NEW FIELD
}
```

## Migration Process

### Step 1: Deploy New Contract

```bash
# Build the new contract
cd op-finality-gadget/contracts/finality
cargo build --release

# Deploy to blockchain
wasmd tx wasm store target/release/finality.wasm --from admin
# Returns: Code ID 456
```

### Step 2: Execute Migration

```bash
# Migrate existing contract to new code
wasmd tx wasm migrate <contract_address> 456 '{"version": "v2.0.0"}' --from admin
```

### Step 3: Verify Migration

```bash
# Check contract info
wasmd query wasm contract <contract_address>

# Query contract to verify functionality
wasmd query wasm contract-state smart <contract_address> '{"config": {}}'
```

## Migration Function Implementation

### Current Implementation (Non-State-Breaking)

The current migration function is simple and handles non-state-breaking
migrations:

```rust
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

### Future State-Breaking Migrations

When you need to handle state-breaking changes, you'll modify the migration
function:

```rust
pub fn migrate(
    deps: DepsMut<BabylonQuery>,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    let mut response = Response::new().add_attribute("action", "migrate");
    
    // Load old config
    let old_config = OLD_CONFIG.load(deps.storage)?;
    
    // Convert to new format
    let new_config = Config {
        admin: old_config.admin,
        bsn_id: old_config.bsn_id,
        min_pub_rand: old_config.min_pub_rand,
        max_finality_providers: 100, // DEFAULT VALUE
        emergency_pause: false,       // DEFAULT VALUE
    };
    
    // Save new config
    NEW_CONFIG.save(deps.storage, &new_config)?;
    
    if let Some(version) = msg.version {
        response = response.add_attribute("version", version);
    }
    
    Ok(response)
}
```

## Testing Migrations

### Unit Tests

The contract includes migration tests:

```bash
# Run migration tests
cargo test test_migrate

# Run all tests
cargo test
```

### Integration Tests

For comprehensive testing, you can create integration tests:

```rust
#[test]
fn test_contract_migration() {
    // Setup test environment
    let mut app = mock_app();
    
    // Deploy v1 contract
    let v1_code_id = app.store_code(contract_v1_wasm);
    let contract_addr = app.instantiate_contract(v1_code_id, /* params */);
    
    // Deploy v2 contract
    let v2_code_id = app.store_code(contract_v2_wasm);
    
    // Test migration
    app.migrate_contract(&contract_addr, v2_code_id, /* migration msg */);
    
    // Verify migration worked
    let config = app.query_contract(&contract_addr, /* query */);
    assert_eq!(config.version, "v2.0.0");
}
```

## Migration Best Practices

### 1. Always Test First

- Test migrations on testnet before mainnet
- Use integration tests to verify migration logic
- Test both success and failure scenarios

### 2. Plan Your Storage Structure

- Design storage structures to be extensible
- Use optional fields when possible
- Plan for future additions

### 3. Version Tracking

- Always include version information in migrations
- Use semantic versioning (v1.0.0, v2.0.0, etc.)
- Log migration events for audit trails

### 4. Rollback Planning

- Have a rollback strategy ready
- Test rollback procedures
- Keep old contract versions available

### 5. Security Considerations

- Only admin should be able to migrate
- Validate migration parameters
- Monitor contract after migration

## Migration Commands Reference

### Deploy Contract
```bash
wasmd tx wasm store contract.wasm --from admin
```

### Migrate Contract
```bash
wasmd tx wasm migrate <contract_address> <new_code_id> '{"version": "v2.0.0"}' --from admin
```

### Query Contract
```bash
wasmd query wasm contract <contract_address>
```

### Query Contract State
```bash
wasmd query wasm contract-state smart <contract_address> '{"config": {}}'
```

## Troubleshooting

### Common Issues

1. **Migration Fails**: Ensure the contract has migration support
2. **State Incompatibility**: Check storage structure changes
3. **Gas Limits**: Complex migrations may require more gas
4. **Permission Errors**: Ensure admin is calling migration

### Debugging

1. Check contract logs for migration events
2. Verify contract state before and after migration
3. Test migration on testnet first
4. Use contract queries to verify functionality

## Future Enhancements

### Planned Features

- [ ] State migration helpers
- [ ] Migration validation tools
- [ ] Automated migration testing
- [ ] Migration rollback functionality

### Migration Patterns

- [ ] Config structure migrations
- [ ] Data format conversions
- [ ] Storage key changes
- [ ] Permission model updates

## Support

For questions about contract migration:

1. Check the test files for examples
2. Review the migration function implementation
3. Test thoroughly before production deployment
4. Consult the CosmWasm migration documentation

## Changelog

### v1.0.0-rc.0
- Added basic migration support
- Implemented non-state-breaking migration function
- Added migration tests
- Updated schema generation for migration messages
