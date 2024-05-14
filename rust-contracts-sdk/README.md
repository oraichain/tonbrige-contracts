# Oraichain Ton Bridge SDK

## Generate code and docs

```bash
# build code:
cwtools build ./rust-contracts/* -o rust-contracts-sdk/packages/contracts-build/data
# gen code:
cwtools gents ./rust-contracts/* -o rust-contracts-sdk/packages/contracts-sdk/src
# gen doc:
yarn docs

# patch a package:
yarn patch-package @cosmjs/cosmwasm-stargate
```
