# TON Trustless bridge EVM contracts and Cosmwasm contracts

by RSquad Blockchain Lab on behalf of TON Foundation, and Oraichain Labs.

## Prerequisites

### Install foundry:

https://ethereum-blockchain-developer.com/2022-06-nft-truffle-hardhat-foundry/14-foundry-setup/

## Setup Hardhat Foundry, Solidity & run tests

```bash
# install deps
yarn

# build forge
forge build

# compile contracts
yarn hardhat compile

# Run tests
yarn test
```

## Code coverage for CosmWasm contracts

Run:

```bash
# in the root workspace directory, run:
cargo tarpaulin --lib --workspace --ignore-tests --target-dir $CARGO_TARGET_DIR -o html
```

## Reference:
https://docs.ton.org/trustless-interaction-with-ton_v1.1_23-05-15.pdf
