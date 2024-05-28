// export const utils = require('./utils');
import iutils from "./utils/index.js";
// export const types = require('./types');
import * as itypes from "./types/index.js";
// import {
//   Address,
//   BitString,
//   Cell,
//   Hashmap,
//   HashmapE,
//   HashmapAug,
//   HashmapAugE,
// } from './types/index.js';
// export types;

// const {Address} = require("./Address");
// const {BitString} = require("./BitString");
// const {Cell} = require("./Cell");
// const Hashmap = require("./Hashmap");

// const providers = require("./providers");
// export const configs = require('./configs');
// import * as iconfigs from "./configs/index";

// const {Contract} = require('./contract/Contract');

// const {AbiContract} = require('./contract/AbiContract');
// const {AbiPackages} = require('./contract/abi');

// const {ClassicContract} = require('./contract/ClassicContract');
// const ClassicContracts = require("./contract/classic");
// const ClassicWallets = require("./contract/classic/wallet");

// export const bc = require('./blockchain');
import * as ibc from "./blockchain/index";
// export const Storages = require('./providers/Storage');
import * as iStorages from "./providers/Storage";

export * from "./block-utils";
export * from "./types/Block.js";

export namespace TonRocks {
  export const version = "0.1.0";

  export const bc = ibc;
  export const Storages = iStorages;
  // export const types = itypes;
  // export const configs = iconfigs;

  export type bc = typeof ibc;
  export type Storages = typeof iStorages;
  // export type types = typeof itypes;
  // export type configs = typeof iconfigs;

  // export const utils = iutils;
  // export type utils = typeof iutils;
  export namespace utils {
    export const BN = iutils.BN;
    export type BN = typeof iutils.BN;
    export const sha256 = iutils.sha256;
    export type sha256 = typeof iutils.sha256;
  }

  export namespace types {
    // export * from './types/index.js';
    export const Address = itypes.Address;
    export const BitString = itypes.BitString;
    export const Cell = itypes.Cell;
    export const Hashmap = itypes.Hashmap;
    export const HashmapE = itypes.HashmapE;
    export const HashmapAug = itypes.HashmapAug;
    export const HashmapAugE = itypes.HashmapAugE;

    export type Address = typeof itypes.Address;
    export type BitString = typeof itypes.BitString;
    export type Cell = any; // typeof itypes.Cell;
    export type Hashmap = typeof itypes.Hashmap;
    export type HashmapE = typeof itypes.HashmapE;
    export type HashmapAug = typeof itypes.HashmapAug;
    export type HashmapAugE = typeof itypes.HashmapAugE;
  }
}

// namespace TonRocks {

// export
// class TonRocks {
//   public static version = version;
//   public static types = types;
//   public static utils = utils;
//   public static bc = bc;
//   public static configs = configs;
//   public static Storages = Storages;

//   version: any;
//   types: any;
//   utils: any;
//   bc: any;
//   Contract: any;
//   AbiContract: any;
//   AbiPackages: any;
//   ClassicContract: any;
//   ClassicWallets: any;
//   ClassicContracts: any;
//   providers: any;
//   configs: any;
//   storages: any;

//   constructor(provider, storage) {
//     this.version = version;

//     this.types = types;
//     this.utils = utils;

//     this.bc = bc;

//     this.bc.Block._provider = provider;
//     if (storage) {
//       this.bc.Block._storage = storage;
//     } else if (typeof window !== 'undefined') {
//       this.bc.Block._storage = new Storages.BrowserStorage('default');
//     }

//     // this.Contract = Contract;
//     this.Contract._provider = provider;
//     // this.AbiContract = AbiContract;
//     // this.AbiPackages = AbiPackages;
//     // this.ClassicContract = ClassicContract;
//     // this.ClassicWallets = ClassicWallets;
//     // this.ClassicContracts = ClassicContracts;

//     // this.providers = providers;
//     this.configs = configs;
//     this.storages = Storages;
//   }
// }

// (TonRocks as any).version = version;

// (TonRocks as any).types = types;
// (TonRocks as any).utils = utils;

// (TonRocks as any).bc = bc;

// // TonRocks.Contract = Contract;
// // TonRocks.AbiContract = AbiContract;
// // TonRocks.AbiPackages = AbiPackages;
// // TonRocks.ClassicContract = ClassicContract;
// // TonRocks.ClassicWallets = ClassicWallets;
// // TonRocks.ClassicContracts = ClassicContracts;

// // TonRocks.providers = providers;
// (TonRocks as any).configs = configs;
// (TonRocks as any).storages = Storages;

// if (typeof window !== 'undefined') {
//   window.TonRocks = TonRocks;
// }

export default TonRocks;
// export default {
//   version,
//   types,
//   utils,
//   bc,
//   configs,
//   Storages,
// };

// module.exports = TonRocks;

// export default TonRocks;

// export namespace TonRocks {
//   version,
//   types,
//   utils,
//   bc,
//   configs,
//   Storages,
// };
// };
