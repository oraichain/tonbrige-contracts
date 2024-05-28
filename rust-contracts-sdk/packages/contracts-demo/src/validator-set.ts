import { parseValidatorSet } from "@ton/ton";
import BN from "bn.js";
import "dotenv/config";
import _ from "lodash";
import { LiteClient, LiteEngine, LiteRoundRobinEngine, LiteSingleEngine } from "ton-lite-client";
import { Functions, liteServer_blockData } from "ton-lite-client/dist/schema";
import {
  ISubTree,
  buildPathToConfig,
  buildProof,
  buildProofExcept,
  makeBocLeaf,
  printPath,
  printTreeVolume
} from "./block-utils";
import { intToIP } from "./common";
import TonRocks from "./ton-rocks-js/index.js";

export interface ParsedBlock {
  global_id: number;
  info: {
    version: number;
    key_block: boolean;
    seq_no: number;
    prev_seq_no: number;
    gen_utime: number;
    prev_key_block_seqno: number;
    start_lt: BN;
    end_lt: BN;
  };
  extra?: {
    custom?: {
      config?: {
        config?: {
          map: Map<string, any>;
        };
      };
    };
  };
}

export async function parseBlock(block: liteServer_blockData): Promise<ParsedBlock> {
  const [rootCell] = await TonRocks.types.Cell.fromBoc(block.data.toString("hex"));

  // Additional check for rootHash
  const rootHash = Buffer.from(rootCell.hashes[0]).toString("hex");
  if (rootHash !== block.id.rootHash.toString("hex")) {
    throw Error("got wrong block or here was a wrong root_hash format");
  }

  const parsedBlock = TonRocks.bc.BlockParser.parseBlock(rootCell);
  return parsedBlock;
}

export async function buildValidatorsData(root: TonRocks.types.Cell): Promise<string[]> {
  const proofParts: string[] = [];

  const p = buildPathToConfig(root);
  if (!p) {
    throw new Error("Path not found");
  }

  // console.log('path ====');
  // console.log(p);
  printPath(p);

  const proof = await buildProof(p, true);
  proof.refs[0] = await buildProof([root.refs[0]]);
  await proof.finalizeTree();
  // console.log('before config refs:');
  // console.log(proof.refs[3].refs[3].refs);

  const parts: ISubTree[] = [];
  // TODO: make better
  printTreeVolume(proof.refs[3].refs[3].refs[proof.refs[3].refs[3].refs.length - 1], parts);
  // console.log('parts:');
  // console.log(parts);

  const partsIndex = parts.reduce((m, p) => {
    const i = Buffer.from(p.root.getHash()).toString("hex");
    m[i] = p;
    return m;
  }, <Record<string, TonRocks.types.Cell>>{});
  const keysPartsIndex = _.keys(partsIndex);
  for (let i = 0; i < parts.length; i++) {
    const leafBoc = await makeBocLeaf(parts[i].root, i, keysPartsIndex);
    // console.log();
    proofParts.push(leafBoc.toString("hex"));
  }

  // console.log('proofParts len:', proofParts.length);

  const proofPruned = await buildProofExcept(proof, keysPartsIndex);
  await proofPruned.finalizeTree();

  // console.log("CELLS SHOULDN'T be pruned", keysPartsIndex);
  // console.log(
  //   'proof before prune',
  //   proof.refs.map((c) => Buffer.from(c.hashes[0]).toString('hex')),
  //   Buffer.from(proof.hashes[0]).toString('hex'),
  // );
  // console.log(
  //   'Prunned block root cell hash (extra):',
  //   proofPruned.refs.map((c) => Buffer.from(c.getHash()).toString('hex')),
  //   // proofPruned.refs[3],
  //   Buffer.from(proofPruned.hashes[0]).toString('hex'),
  // );
  const bocProofPruned = await proofPruned.toBoc(false);

  const hexBoc = Buffer.from(bocProofPruned).toString("hex");
  proofParts.unshift(hexBoc);

  return proofParts;
}

(async () => {
  const { liteservers } = await fetch("https://ton.org/global.config.json").then((data) => data.json());
  // Personal choice. Can choose a different index if needed
  const server = liteservers[0];

  const engines: LiteEngine[] = [];
  engines.push(
    new LiteSingleEngine({
      host: `tcp://${intToIP(server.ip)}:${server.port}`,
      publicKey: Buffer.from(server.id.key, "base64")
    })
  );
  const engine: LiteEngine = new LiteRoundRobinEngine(engines);
  const client = new LiteClient({ engine });
  console.log("get master info");
  const master = await client.getMasterchainInfo();
  console.log("master", master);

  // key block. Got this by querying a block, then deserialize it, then find prev_key_block_seqno
  // it has to be a key block to include validator set & block extra to parse into the contract
  const initKeyBlockSeqno = 38103071;
  const fullBlock = await client.getFullBlock(initKeyBlockSeqno);
  const initialKeyBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initKeyBlockSeqno);
  // console.log(initialKeyBlockInformation);
  const blockConfig = await client.getConfig(initialKeyBlockInformation, {
    awaitSeqno: initialKeyBlockInformation.seqno
  });
  const validatorSetCell = blockConfig.config.get(34);

  // TODO: need to proof that this validator set is valid
  const validators = parseValidatorSet(validatorSetCell.beginParse());
  // console.dir(validators, { depth: null });

  // get block
  const block = await engine.query(Functions.liteServer_getBlock, {
    kind: "liteServer.getBlock",
    id: {
      kind: "tonNode.blockIdExt",
      ...initialKeyBlockInformation
    }
  });

  const [rootCell] = await TonRocks.types.Cell.fromBoc(block.data.toString("hex"));
  const parsedBlock = await parseBlock(block);
  console.log(parsedBlock.extra.custom.config.config.map.get("22")); // 34 in decimals. 34 is the index of validator set
  const parsedBlockData = await buildValidatorsData(rootCell);
  console.dir(parsedBlockData[0]);

  engine.close();
})();
