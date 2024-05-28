# Oraichain Ton Bridge SDK

## Generate code and docs

```bash
# build code:
cwtools build ./rust-contracts/* -o rust-contracts-sdk/packages/contracts-build/data
# build schema
cwtools build ./rust-contracts/* -s
# gen code:
cwtols gents ./rust-contracts/* -o rust-contracts-sdk/packages/contracts-sdk/srco
# gen doc:
yarn docs

# patch a package:
yarn patch-package @cosmjs/cosmwasm-stargate
```
