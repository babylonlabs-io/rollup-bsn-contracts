# Data Pruning Guidelines

This document provides guidelines for contract administrators on how to use the data pruning functionality in the Rollup BSN finality contract.

## Overview

The BSN finality contract stores three types of data that can grow indefinitely over time:

1. **Finality Signatures** - Cryptographic signatures from finality providers for each finalized block.
2. **Signatories by Block Hash** - Records of which finality providers signed each block.
3. **Public Randomness Values** - Pre-committed randomness values used in finality signatures.

To prevent unlimited storage growth and manage gas costs, the contract provides a unified pruning mechanism that allows administrators to remove old data safely.

## When to Prune

### Pruning Triggers

Consider pruning when:

- **Storage Growth**: The contract's storage size is approaching limits or causing high gas costs.
- **Performance Degradation**: Query operations are becoming slow due to large datasets.
- **Operational Maintenance**: Regular maintenance to keep the contract efficient.
- **Cost Management**: Reducing ongoing storage costs on the blockchain.

### Safety Considerations

**CRITICAL**: Pruning is irreversible. Once data is pruned, it cannot be recovered. Consider these factors before pruning:

1. **Chain Reorganization Safety**: Ensure the pruning height provides sufficient safety margin for potential chain reorganizations.
2. **Data Submission Delays**: Account for delays in finality signature submissions.
3. **Dispute Periods**: Consider any dispute or challenge periods that might require historical data.
4. **Audit Requirements**: Ensure compliance with any audit or regulatory requirements.

### Recommended Pruning Height

A conservative approach is to prune data that is:
- **At least 1000 blocks old** from the current rollup height.
- **Beyond any reasonable chain reorganization depth** (typically 100-500 blocks).
- **After any dispute periods** have expired.

## How to Prune

### Pruning Message

Use the `PruneData` message with the following parameters:

```json
{
  "prune_data": {
    "rollup_height": 10000,
    "max_signatures_to_prune": 50,
    "max_pub_rand_values_to_prune": 50
  }
}
```

### Parameters

- **`rollup_height`** (required): Remove all data for rollup blocks with height ≤ this value.
- **`max_signatures_to_prune`** (optional): Maximum number of finality signatures and signatories to prune in one operation.
  - Default: 50
  - Use `Some(0)` to disable pruning of signatures/signatories for this call
  - Maximum: 100
- **`max_pub_rand_values_to_prune`** (optional): Maximum number of public randomness values to prune in one operation.
  - Default: 50
  - Use `Some(0)` to disable pruning of public randomness values for this call
  - Maximum: 100

### Pruning Strategy

#### Incremental Pruning

For large datasets, use incremental pruning to avoid gas limits:

1. **Start with smaller limits**: Use `max_signatures_to_prune: 25` and `max_pub_rand_values_to_prune: 25`.
2. **Monitor gas usage**: Check transaction gas consumption.
3. **Increase gradually**: If gas usage is acceptable, increase limits.
4. **Repeat until complete**: Continue until all desired data is pruned.

#### Selective Pruning

You can selectively prune different data types:

- **Signatures only**: Set `max_pub_rand_values_to_prune: Some(0)`.
- **Public randomness only**: Set `max_signatures_to_prune: Some(0)`.
- **All data**: Provide both parameters (or use defaults).

## Pruning Frequency

### Recommended Schedule

- **Weekly**: For active networks with high transaction volume.
- **Monthly**: For moderate activity networks.
- **Quarterly**: For low activity networks.
- **On-demand**: When storage costs become significant.

### Monitoring

Monitor these metrics to determine pruning frequency:

1. **Storage Size**: Track contract storage growth over time.
2. **Gas Costs**: Monitor transaction costs for queries and operations.
3. **Performance**: Track query response times.
4. **Data Age**: Monitor the age of oldest stored data.

## Example Pruning Scenarios

### Scenario 1: Regular Maintenance

**Goal**: Keep storage manageable with weekly pruning.

```json
{
  "prune_data": {
    "rollup_height": "current_height - 1000",
    "max_signatures_to_prune": 50,
    "max_pub_rand_values_to_prune": 50
  }
}
```

### Scenario 2: Large Dataset Cleanup

**Goal**: Clean up a large backlog of old data.

**Step 1**: Start with conservative limits
```json
{
  "prune_data": {
    "rollup_height": "current_height - 2000",
    "max_signatures_to_prune": 25,
    "max_pub_rand_values_to_prune": 25
  }
}
```

**Step 2**: Increase limits if gas usage is acceptable
```json
{
  "prune_data": {
    "rollup_height": "current_height - 2000",
    "max_signatures_to_prune": 75,
    "max_pub_rand_values_to_prune": 75
  }
}
```

### Scenario 3: Emergency Storage Management

**Goal**: Quickly reduce storage when approaching limits

```json
{
  "prune_data": {
    "rollup_height": "current_height - 500",
    "max_signatures_to_prune": 100,
    "max_pub_rand_values_to_prune": 100
  }
}
```

## Best Practices

### Before Pruning

1. **Backup**: Ensure you have off-chain backups of critical data.
2. **Verify**: Double-check the pruning height is safe.
3. **Test**: Test pruning on a testnet if available.
4. **Notify**: Inform stakeholders about planned maintenance.

### During Pruning

1. **Monitor**: Watch transaction execution and gas usage.
2. **Log**: Keep records of pruning operations.
3. **Verify**: Confirm data was pruned as expected.
4. **Document**: Record the pruning height and results.

### After Pruning

1. **Validate**: Verify contract state is correct.
2. **Monitor**: Watch for any unexpected behavior.
3. **Update**: Update operational procedures if needed.
4. **Schedule**: Plan the next pruning operation.

## Troubleshooting

### Common Issues

1. **Gas Limit Exceeded**: Reduce `max_signatures_to_prune` or `max_pub_rand_values_to_prune`.
2. **No Data Pruned**: Check if `rollup_height` is too low.
3. **Partial Pruning**: Some data types may have different age distributions.

### Error Handling

- **Unauthorized**: Ensure you're using the admin account.
- **Invalid Parameters**: Check parameter values and types.
- **Storage Errors**: Verify contract has sufficient gas for the operation.

## Monitoring and Alerts

### Key Metrics to Track

1. **Storage Growth Rate**: Bytes per block or per day.
2. **Oldest Data Age**: Age of oldest stored data.
3. **Pruning Frequency**: Time between pruning operations.
4. **Gas Costs**: Average gas cost for queries and operations.

### Recommended Alerts

- Storage size approaching 80% of limits.
- Oldest data older than 30 days.
- Gas costs exceeding normal thresholds.
- Failed pruning operations.

## Conclusion

Data pruning is a critical operational task for maintaining the efficiency and cost-effectiveness of the BSN finality contract. By following these guidelines and maintaining a regular pruning schedule, administrators can ensure the contract remains performant and cost-effective while preserving the safety and integrity of the system.

Remember: **When in doubt, be conservative**. It's better to prune less frequently or with smaller limits than to risk removing data that might still be needed. 