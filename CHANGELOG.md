# Changelog

## [Unreleased](https://github.com/babylonlabs-io/op-finality-gadget/tree/HEAD)

[Full Changelog](https://github.com/babylonlabs-io/op-finality-gadget/compare/v0.14.1...HEAD)

## [v0.14.1](https://github.com/babylonlabs-io/op-finality-gadget/tree/v0.14.1) (2025-05-15)

[Full Changelog](https://github.com/babylonlabs-io/op-finality-gadget/compare/v0.13.0-rc.0...v0.14.1)

 **Merged pull requests:**

- F/add CI [\#1](https://github.com/babylonlabs-io/op-finality-gadget/pull/1) ([maurolacy](https://github.com/maurolacy))

## [v0.14.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.14.0) (2025-05-14)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.13.0-rc.0...v0.14.0)

**Closed issues:**

- Go over TODOs and create issues [\#116](https://github.com/babylonlabs-io/babylon-contract/issues/116)

**Merged pull requests:**

- f/TODOs annotation [\#135](https://github.com/babylonlabs-io/babylon-contract/pull/135) ([maurolacy](https://github.com/maurolacy))

## [v0.13.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.13.0) (2025-02-11)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.12.0-rc.0...v0.13.0)

## [v0.12.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.12.0) (2025-02-07)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.11.0-rc.1...v0.12.0)

**Closed issues:**

**Merged pull requests:**

- feat: op consumer chain slashing \(2/2\) [\#98](https://github.com/babylonlabs-io/babylon-contract/pull/98) ([parketh](https://github.com/parketh))
- chore: use query\_grpc from cosmwasm\_std [\#93](https://github.com/babylonlabs-io/babylon-contract/pull/93) ([lesterli](https://github.com/lesterli))
- feat: op consumer chain slashing \(1/2\) [\#92](https://github.com/babylonlabs-io/babylon-contract/pull/92) ([parketh](https://github.com/parketh))

## [v0.11.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.11.0) (2024-11-19)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.10.0-rc.0...v0.11.0)


**Closed issues:**

- OP: integration test vs. unit test [\#18](https://github.com/babylonlabs-io/babylon-contract/issues/18)

## [v0.10.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.10.0) (2024-10-08)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.9.0-rc.1...v0.10.0)

**Merged pull requests:**

- \[OP\] chore: remove unused activated\_height [\#77](https://github.com/babylonlabs-io/babylon-contract/pull/77) ([bap2pecs](https://github.com/bap2pecs))
- F/stock optimizer [\#76](https://github.com/babylonlabs-io/babylon-contract/pull/76) ([maurolacy](https://github.com/maurolacy))
- Fix: proper name for the full wasm checks job [\#75](https://github.com/babylonlabs-io/babylon-contract/pull/75) ([maurolacy](https://github.com/maurolacy))
- F/optimizer ci [\#73](https://github.com/babylonlabs-io/babylon-contract/pull/73) ([maurolacy](https://github.com/maurolacy))
- Fix/optimizer [\#72](https://github.com/babylonlabs-io/babylon-contract/pull/72) ([maurolacy](https://github.com/maurolacy))
- Change license to BSL [\#50](https://github.com/babylonlabs-io/babylon-contract/pull/50) ([maurolacy](https://github.com/maurolacy))

## [v0.9.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.9.0) (2024-08-29)

[Full Changelog](https://github.com/babylonlabs-io/babylon-contract/compare/v0.8.0-rc.1...v0.9.0)

**Fixed bugs:**

**Merged pull requests:**

- Try and enable CI release jobs [\#48](https://github.com/babylonlabs-io/babylon-contract/pull/48) ([maurolacy](https://github.com/maurolacy))
- Add GH actions workflow [\#30](https://github.com/babylonlabs-io/babylon-contract/pull/30) ([maurolacy](https://github.com/maurolacy))
- Migrate repo [\#26](https://github.com/babylonlabs-io/babylon-contract/pull/26) ([maurolacy](https://github.com/maurolacy))

## [v0.8.0](https://github.com/babylonchain/babylon-contract/tree/v0.8.0) (2024-07-09)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.7.0...v0.8.0)

**Closed issues:**

**Merged pull requests:**

- fix: allow query_block_voters() to return `None` if the block doesn't exist (#204)
- chore: refactor pub rand commit (#200)
- feat: add the query msg `FirstPubRandCommit ` and `Event` (#198)
- feat: add query msg `HasPubRandCommit` (#196)
- fix: decode hex hash (#195)
- feat: set `isEnabled` at instantiation (#193)
- feat: update admin (#192)
- fix: cannot compare babylon chain height with consumer chain height (#190)
- test: add finality gadget tests (#188)
- chore: clean up scripts/optimizer.sh (#187)

## [v0.7.0](https://github.com/babylonlabs-io/babylon-contract/tree/v0.7.0) (2024-06-24)

[Full Changelog](https://github.com/babylonchain/babylon-contract/compare/v0.6.0...v0.7.0)

**Closed issues:**

- add a killswitch to disable finality gadget [\#181](https://github.com/babylonchain/babylon-contract/issues/181)
- Set an activated height when deploying the op-finality-gadget contract [\#167](https://github.com/babylonchain/babylon-contract/issues/167)
- Store block hash in the op-finality-gadget contract [\#159](https://github.com/babylonchain/babylon-contract/issues/159)
- Upgrade to CosmWasm 2.x [\#140](https://github.com/babylonchain/babylon-contract/issues/140)

**Merged pull requests:**

- fix: build-optimizer.sh to properly generate code for arm64 [\#185](https://github.com/babylonchain/babylon-contract/pull/185) ([bap2pecs](https://github.com/bap2pecs))
- fix: init pr empty issue [\#184](https://github.com/babylonchain/babylon-contract/pull/184) ([bap2pecs](https://github.com/bap2pecs))
- feat: implement killswitch [\#182](https://github.com/babylonchain/babylon-contract/pull/182) ([parketh](https://github.com/parketh))
- fix: comment out unused code [\#146](https://github.com/babylonchain/babylon-contract/pull/146) ([bap2pecs](https://github.com/bap2pecs))
- chore: change to query block votes [\#178](https://github.com/babylonchain/babylon-contract/pull/178) ([lesterli](https://github.com/lesterli))
- feat: query last pub rand commit [\#177](https://github.com/babylonchain/babylon-contract/pull/177) ([lesterli](https://github.com/lesterli))
- \[op finality gadget\] feat: add QueryMsg::QueryBlockFinalized \(part 2\) [\#174](https://github.com/babylonchain/babylon-contract/pull/174) ([bap2pecs](https://github.com/bap2pecs))
- chore: move queries [\#173](https://github.com/babylonchain/babylon-contract/pull/173) ([lesterli](https://github.com/lesterli))
- chore: simplify the naming [\#171](https://github.com/babylonchain/babylon-contract/pull/171) ([lesterli](https://github.com/lesterli))
- \[op finality gadget\] feat: add QueryMsg::QueryBlockFinalized \(part 1\) [\#170](https://github.com/babylonchain/babylon-contract/pull/170) ([bap2pecs](https://github.com/bap2pecs))
- fix: typo [\#169](https://github.com/babylonchain/babylon-contract/pull/169) ([lesterli](https://github.com/lesterli))
- feat: set activated height [\#168](https://github.com/babylonchain/babylon-contract/pull/168) ([lesterli](https://github.com/lesterli))
- feat: Use gRPC to query the Babylon Chain [\#158](https://github.com/babylonchain/babylon-contract/pull/158) ([lesterli](https://github.com/lesterli))
- Update protocgen.sh [\#156](https://github.com/babylonchain/babylon-contract/pull/156) ([lesterli](https://github.com/lesterli))
- U/cosmwasm 2.x [\#151](https://github.com/babylonchain/babylon-contract/pull/151) ([maurolacy](https://github.com/maurolacy))
- \[op finality gadget\] feat: 5/x - add CommitPublicRandomness and SubmitFinalitySignature [\#150](https://github.com/babylonchain/babylon-contract/pull/150) ([bap2pecs](https://github.com/bap2pecs))
- \[op finality gadget\] feat: 2/x - set admin and consumer chain while instantiating [\#147](https://github.com/babylonchain/babylon-contract/pull/147) ([bap2pecs](https://github.com/bap2pecs))
- \[op finality gadget\] feat: 1/x - set up crate skeleton  [\#144](https://github.com/babylonchain/babylon-contract/pull/144) ([bap2pecs](https://github.com/bap2pecs))
- docs: add missing instruction before running test [\#143](https://github.com/babylonchain/babylon-contract/pull/143) ([bap2pecs](https://github.com/bap2pecs))
- Fix build-optimizer.sh to properly generate code for arm64 [\#142](https://github.com/babylonchain/babylon-contract/pull/142) ([bap2pecs](https://github.com/bap2pecs))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
