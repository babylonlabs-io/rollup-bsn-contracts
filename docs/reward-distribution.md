# Rollup BSN Reward Distribution

## Table of Contents

1. [Introduction](#introduction)
2. [Reward Bridging Strategy](#1-reward-bridging-strategy)
3. [Reward Distribution Process](#2-reward-distribution-process)
4. [Message Structure](#3-message-structure)
5. [Distribution Calculation](#4-distribution-calculation)

## Introduction

Rollup BSNs must bridge rewards to the Babylon Genesis chain, where they are
distributed to finality providers, their delegators, and protocol revenue.
Tokens can be bridged from any supported source and are received through the
`x/bank` module.

> **📖 For detailed information about the reward mechanism and best practices,
> see the 
> [Babylon Rewards Distribution Guide](https://github.com/babylonlabs-io/babylon/blob/release/v3.x/x/btcstaking/docs/rewards-distribution.md).**

Distribution is then handled by the 
[x/incentive module](https://github.com/babylonlabs-io/babylon/tree/v3.0.0-rc.2/x/incentive),
which manages the allocation of rewards to finality providers, delegators, and
protocol revenue.

> **Babylon Genesis** supports multiple bridging methods for transferring tokens
> into the `x/bank` module, including: [Union](https://union.build/), 
> [IBCEureka](https://cosmos.network/ibc-eureka/), and standard
> [IBC](https://cosmos.network/ibc/) for Cosmos chains. For the reward
> mechanism, the only requirement is that tokens ultimately arrive in `x/bank`.

> **⚠️ Important**: CW-20 assets are *not* supported.

> **Important**: The only requirement is that tokens must be present in a specific account within the `x/bank` module on Babylon Genesis before distribution can occur.

## 1. Reward Distribution Process

> **Note**: The reward interval is the time period between reward distributions.
> This interval is not predefined by the protocol, each BSN is responsible for
> controlling their own distribution frequency and interval length.

The reward distribution process follows a four-step strategy:

1. **Bridge tokens to x/bank** on Babylon Genesis
2. **Calculate total rewards** for the current reward interval
3. **Calculate distribution ratios** for finality providers (you can reference
   voting tables from the [Rollup Finality Gadget](https://github.com/babylonlabs-io/rollup-finality-gadget) 
   or use any distribution scheme you choose)
4. **Submit MsgAddBsnRewards** message to Babylon Genesis to distribute rewards

> **Note**: BSNs can choose to bridge tokens in bulk (maintaining a balance) or
> just-in-time (before each distribution), depending on their operational
> preferences.

During [BSN registration](contract-management.md#5-rollup-bsn-registration), a
fixed protocol commission rate is set. When distributing rewards via
`MsgAddBsnRewards`, the BSN specifies the total reward amount and finality
provider distribution ratios, while the protocol commission remains fixed at the
registration rate.

> **Note**: Rewards are distributed to delegators based on their active stakes
> at the time the distribution message is submitted. Delegators who unbond
> before distribution may miss rewards, so **frequent distributions minimize this risk**.

## 3. Message Structure

BSN rewards are distributed through the submission of a `MsgAddBsnRewards` message to the Babylon Genesis chain.

**Message Format:**
```go
type MsgAddBsnRewards struct {
	// Sender is the babylon address which will pay for the rewards
	Sender string `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	// BsnConsumerId is the ID of the BSN consumer
	BsnConsumerId string `protobuf:"bytes,2,opt,name=bsn_consumer_id,json=bsnConsumerId,proto3" json:"bsn_consumer_id,omitempty"`
	// TotalRewards is the total amount of rewards to be distributed
	TotalRewards github_com_cosmos_cosmos_sdk_types.Coins `protobuf:"bytes,3,rep,name=total_rewards,json=totalRewards,proto3,castrepeated=github.com/cosmos/cosmos-sdk/types.Coins" json:"total_rewards"`
	// FpRatios is a list of finality providers and their respective reward distribution ratios
	FpRatios []FpRatio `protobuf:"bytes,4,rep,name=fp_ratios,json=fpRatios,proto3" json:"fp_ratios"`
}
```

### Field Explanations

- **`Sender`**: Babylon address (bbn...) that will pay for the rewards
  - Must have sufficient balance to cover `TotalRewards`
  - Account must be in the `x/bank` module

- **`BsnConsumerId`**: Unique identifier for the BSN
  - Must match the ID used during BSN registration
  - Unregistered IDs will be rejected

- **`TotalRewards`**: Total reward amount and denomination to be distributed
  - Must be available in the `Sender` account
  - Supports multiple coin types in a single distribution
  - Protocol commission is automatically deducted based on registration rate

- **`FpRatios`**: Finality provider distribution ratios
  - Maps finality provider public keys to reward portions
  - All portions must sum to `1.0`
  - All finality providers must be registered and have active delegations

> **Critical**: The `Sender` account must have sufficient coins to cover the
> `TotalRewards` amount before submitting the message.

> **Note**: BSNs are responsible for calculating finality provider distribution
> ratios. You can reference voting tables from the 
> [Rollup Finality Gadget](https://github.com/babylonlabs-io/rollup-finality-gadget) or use any
> distribution method they choose.



