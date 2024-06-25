# Oraichain Ton Bridge SDK

## Generate code and docs

```bash
# build code:
cwtools build ./contracts/* -o rust-contracts-sdk/packages/contracts-build/data
# build schema
cwtools build ./contracts/* -s
# gen code:
cwtools gents ./contracts/* -o rust-contracts-sdk/packages/contracts-sdk/src
# gen doc:
yarn docs

# patch a package:
yarn patch-package @cosmjs/cosmwasm-stargate
```
