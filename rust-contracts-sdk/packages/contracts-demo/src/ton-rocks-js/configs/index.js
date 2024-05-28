// const {BlockId} = require("../blockchain/BlockId");
import { BlockId } from "../blockchain/BlockId.js";

// const rocksTestnetConfig = require('./test.rocks.config.json');
// const freetonTestnetConfig = require('./ton-global.config.json');
import rocksTestnetConfig from './test.rocks.config.json' assert { type: "json" };
import freetonTestnetConfig from './ton-global.config.json' assert { type: "json" };


class NetworkOptions {
    constructor(config) {
        if (config["@type"] != 'config.global')
            throw Error('Invalid config');
        this.config = config;
        this.zero_state = new BlockId(config.validator.zero_state || config.validator.init_block);
        this.liteservers = config.liteservers;
        this.wssProxies = {};
        for (let i in this.liteservers) {
            if (this.liteservers[i].ws) {
                this.wssProxies[this.liteservers[i].ip] = this.liteservers[i].ws;
            }
        }
    }
}

export const RocksTestnet = new NetworkOptions(rocksTestnetConfig);
export const FreetonTestnet = new NetworkOptions(freetonTestnetConfig);

// module.exports = {RocksTestnet, FreetonTestnet};
