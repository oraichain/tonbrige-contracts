// block-utils

import _ from "lodash";

import BN from "bn.js";
import { loadHashmap } from "./ton-rocks-js/blockchain/BlockParser.js";
import TonRocks from "./ton-rocks-js/index.js";

type TBN = typeof TonRocks.utils.BN;

export interface ISubTree {
  root: TonRocks.types.Cell;
  parentCell: TonRocks.types.Cell;
  refIndex: number;
}

interface TPrintTreeVolumeRet {
  volume: number;
  parts: ISubTree[];
}

export const printTreeVolume = (root: TonRocks.types.Cell, parts: ISubTree[]): TPrintTreeVolumeRet => {
  const { refs }: { refs: TonRocks.types.Cell[] } = root;
  // const parts: ISubTree[] = [];

  let volCurrent = 1;

  if (refs.length) {
    const vols = refs.map((ref: TonRocks.types.Cell) => {
      const t = printTreeVolume(ref, parts);
      // parts.concat(t.parts)
      return t.volume;
    });

    // console.log(vols);

    // volCurrent += vol;
    const v = vols.reduce((a: number, vol: TonRocks.types.Cell) => a + vol);

    if (v > 64) {
      // if ( v > 52 ) {
      // if ( v > 100 ) {
      vols.forEach((vol, refIndex) => {
        if (vol > 32) {
          parts.push({
            root: refs[refIndex],
            parentCell: root,
            refIndex
          });
        } else {
          volCurrent += vol;
        }
      });
    } else {
      volCurrent += v;
    }
  }

  // console.log('parts:', parts);

  return { volume: volCurrent, parts };
};

export const makeBocLeaf = async (
  root: TonRocks.types.Cell,
  idx: number,
  listExcept: string[] = []
): Promise<Buffer> => {
  // const bocLeaf = await (await cloneTree(parts[0].root)).toBoc(false);
  // const bocLeaf = await buildBoc(root);
  // console.log(root);
  // const bocLeaf = await root.toBoc(false);
  const rootLeaf = await buildProofExcept(root, listExcept);
  await rootLeaf.finalizeTree();
  // console.log('leaf hash:', Buffer.from(rootLeaf.hashes[0]).toString('hex'));
  const bocLeaf = await rootLeaf.toBoc(false);
  const bufLeaf = Buffer.from(bocLeaf);
  // console.log(`=== begin bocLeaf ${idx} ===`);
  // console.log('=== begin bocConfigParams ===');
  // console.log(bufLeaf.toString('hex'));
  // console.log(Buffer.from(bocConfigParams).toString('hex'));
  // console.log(`=== end bocLeaf ${idx} ===`);

  return bufLeaf;
};

export const checkBoc = async (boc: string): Promise<TonRocks.types.Cell> => {
  const cells = await TonRocks.types.Cell.fromBoc(boc);
  const cellsRoot = cells[0];
  // console.log(
  //   '=== root_hash:',
  //   Buffer.from(cellsRoot.getHash()).toString('hex'),
  //   '===',
  // );

  // console.log("BLOCK PARSING BEGIN");
  // const parsedBlock = TonRocks.bc.BlockParser.parseBlock(cellsRoot);
  // console.log("BLOCK PARSING END");

  return cellsRoot;
};

export const cloneCell = (c: TonRocks.types.Cell, proof: boolean = true): TonRocks.types.Cell => {
  // if ( c.isExotic ) {
  //   const type = c.bits.readUint8(0);
  //   if ( type == TonRocks.types.Cell.PrunnedBranchCell ) {
  //     return c;
  //   }
  // }
  const cell = new TonRocks.types.Cell();
  // cell.bits.writeBitString(c.bits);
  cell.bits = c.bits;
  cell.levelMask = c.levelMask;
  cell.isExotic = c.isExotic;
  cell.hasHashes = c.hasHashes;
  cell.proof = proof;
  return cell;
  // return c;
};

export const createPrunnedBranchCell = async (hash: Uint8Array, depth: number): Promise<TonRocks.types.Cell> => {
  const cell = new TonRocks.types.Cell();
  cell.isExotic = true;
  cell.bits = new TonRocks.types.BitString(288);
  cell.bits.writeUint(1 /* TonRocks.types.Cell.PrunnedBranchCell */, 8);
  cell.bits.writeUint(1, 8);
  cell.bits.writeBytes(hash);
  cell.bits.writeUint(depth, 16);
  await cell.finalize();
  return cell;
};

export const buildProofExcept = async (
  rootCell: TonRocks.types.Cell,
  listExcept: string[]
): Promise<TonRocks.types.Cell> => {
  // console.log('buildProofExcept rootCell:', Buffer.from(rootCell.getHash()).toString('hex'));
  // console.log('buildProofExcept listExcept:', listExcept);

  const proof = cloneCell(rootCell);
  // console.log('cloned');
  // console.log(rootCell.refs);
  for (let i in rootCell.refs) {
    // console.log('ref:', i);
    const c = rootCell.refs[i];
    const hash = c.getHash();

    const hexHash = Buffer.from(hash).toString("hex");
    // console.log(hexHash);
    if (-1 == listExcept.findIndex((el) => el == hexHash)) {
      // proof.refs[i] = await cloneTree(c);
      proof.refs[i] = await buildProofExcept(c, listExcept);
    } else {
      // console.log('prune', hexHash);
      proof.refs[i] = await createPrunnedBranchCell(hash, c.depth[0]);
    }
  }

  return proof;
};

export const cloneTree = async (c: TonRocks.types.Cell): Promise<TonRocks.types.Cell> => {
  const r = cloneCell(c);
  // console.log('clone:', Buffer.from(c.getHash()).toString('hex'));

  for (let i in c.refs) {
    r.refs[i] = await cloneTree(c.refs[i]);
  }

  return r;
};

// block.extra.account_blocks.*
export const buildPath = (hexHash: string, c: TonRocks.types.Cell): TonRocks.types.Cell[] | null => {
  const hash = Buffer.from(c.getHash()).toString("hex");
  if (hash == hexHash) {
    return [c];
  }
  for (let i in c.refs) {
    const p = buildPath(hexHash, c.refs[i]);
    if (p) {
      p.unshift(c);
      return p;
    }
  }
  return null;
};

export const buildProof = async (
  path: TonRocks.types.Cell[] = [],
  cloneTail: boolean = false,
  markCellsAsProof: boolean = true
): Promise<TonRocks.types.Cell> => {
  const rootCell = path[0];

  // if( cloneTail && path.length == 1 ) {
  //   // return cloneTree(rootCell);
  //   return rootCell;
  // }

  const proof = cloneCell(rootCell, markCellsAsProof);
  for (let i in rootCell.refs) {
    const c = rootCell.refs[i];
    const hash = c.getHash();
    let flag = false;
    if (path.length > 1) {
      const hexHash1 = Buffer.from(hash).toString("hex");
      const hexHash2 = Buffer.from(path[1].getHash()).toString("hex");
      // console.log({ i, hexHash1, hexHash2 });
      // console.log(path.length, hexHash2);
      flag = hexHash1 == hexHash2;
    }
    if (flag) {
      proof.refs[i] = await buildProof(path.slice(1), cloneTail, markCellsAsProof);
    } else {
      if (cloneTail && path.length == 1) {
        proof.refs[i] = await cloneTree(c);
        // proof.refs[i] = c;
      } else {
        // if ( c.isExotic ) {
        const type = c.bits.readUint8(0);
        if (type == TonRocks.types.Cell.PrunnedBranchCell) {
          proof.refs[i] = c;
        } else {
          // }
          proof.refs[i] = await createPrunnedBranchCell(hash, c.depth[0]);
        }
      }
    }

    // const hash2 = proof.refs[i].getHash();
    // logRequire(
    // // console.log(
    //   `proof.refs[${ i }]`,
    //   Buffer.from(hash).toString('hex'),
    //   Buffer.from(hash2).toString('hex'),
    // );
  }

  // console.log(proof);
  return proof;
};

export const printPath = (p: TonRocks.types.Cell[]): void => {
  // console.log(
  //   'path:',
  //   p.map((c: TonRocks.types.Cell) => Buffer.from(c.getHash()).toString('hex')),
  // );
};

export const printTreeList = (root: TonRocks.types.Cell, prefix: string = ""): void => {
  // console.log(root);
  const cellToHexId = (c: TonRocks.types.Cell) => Buffer.from(c.getHash()).toString("hex");
  const hexCurrentId = cellToHexId(root);
  const { refs } = root;
  // console.log(prefix, hexCurrentId, refs.length);
  refs.forEach((ref: TonRocks.types.Cell) => {
    printTreeList(ref, " " + prefix);
  });
  // if ( refs[0] ) {
  //   printTreeList(refs[0], ' ' + prefix);
  // }
};

// const loadHashmap = TonRocks.bc.BlockParser.loadHashmap;
// const loadValidatorDescr = TonRocks.bc.BlockParser.loadValidatorDescr;

/*
  block_extra in_msg_descr:^InMsgDescr
    out_msg_descr:^OutMsgDescr
    account_blocks:^ShardAccountBlocks
    rand_seed:bits256
    created_by:bits256
    custom:(Maybe ^McBlockExtra) = BlockExtra;

  block#11ef55aa global_id:int32
    info:^BlockInfo value_flow:^ValueFlow
    state_update:^(MERKLE_UPDATE ShardState)
    extra:^BlockExtra = Block;
*/

/*
  [
    '4b36c905aaacd2759c71ffb04a326ef6a8957bedc2c0e59f549fbc1faf14f0a0',
    'e13316b7b71f3ef71ecc164faa9ecabcfff421b55db0f70860c5a5d8ca53a864',
    '0553ca3f1baaca4946c539346767e1b3c2363a79793ecaf180a21949e27ca5fc',
    'ea311f089398664591a74e6eeed210b8f998cc04045e33423f0e62a766b1ef15',
    '79a8e7d60e6701f44cafd207123d0e2f2940db0504fb930c50cf6bf8c50b9b50',
    '084677d2ce55f23add04598157281500fbede743bee00f86428e5bd90844993f',
    '9fe1cfec07c9d9871d96bcdcfed5388c0c090e9c203c13d486cf75b4fbc1b140',
    '75158b8d61fcadd97a1300030b53bb9ca66b78f8e6e5619a4c7a74de390bdf33',
    'bc24d063b6a5117c7262bd116448b7336b187327874dcef4376bf2c44ebe8937'
  ]
*/
const { loadBit, loadUint16, loadRefIfExist } = TonRocks.bc;

export const buildPathToConfig = (c: TonRocks.types.Cell): TonRocks.types.Cell[] | null => {
  const path: TonRocks.types.Cell[] = [];
  path.push(c);

  // block#11ef55aa global_id:int32
  //   info:^BlockInfo value_flow:^ValueFlow
  //   state_update:^(MERKLE_UPDATE ShardState)
  //   extra:^BlockExtra = Block;
  const extra = c.refs[3];
  // console.log('extra');
  // console.log(extra);
  path.push(extra);

  // block_extra in_msg_descr:^InMsgDescr
  //   out_msg_descr:^OutMsgDescr
  //   account_blocks:^ShardAccountBlocks
  //   rand_seed:bits256
  //   created_by:bits256
  //   custom:(Maybe ^McBlockExtra) = BlockExtra;
  // const custom = extra.refs[3];
  const custom = extra.refs[extra.refs.length - 1];
  // console.log('custom');
  // console.log(custom);
  path.push(custom);

  // masterchain_block_extra#cca5
  //   key_block:(## 1)
  //   shard_hashes:ShardHashes
  //   shard_fees:ShardFees
  //   ^[ prev_blk_signatures:(HashmapE 16 CryptoSignaturePair)
  //     recover_create_msg:(Maybe ^InMsg)
  //     mint_msg:(Maybe ^InMsg) ]
  //   config:key_block?ConfigParams
  // = McBlockExtra;

  // function loadMcBlockExtra(cell, t) {
  const t = { cs: 0, ref: 0 };
  if (loadUint16(custom, t) !== 0xcca5) {
    // throw Error("not a McBlockExtra");
    console.log("not a McBlockExtra");
    return null;
  }
  const keyBlock = loadBit(custom, t);
  // console.log({ keyBlock, refs: custom.refs });
  //   let data = {_:"McBlockExtra"};
  //   data.key_block = loadBit(cell, t);
  //   data.shard_hashes = loadShardHashes(cell, t);
  //   data.shard_fees = loadShardFees(cell, t);

  //   let cell_r1 = cell.refs[t.ref++];
  //   let tr1 = {cs: 0, ref: 0};
  //   if (cell_r1.type === Cell.OrdinaryCell) {
  //     data.prev_blk_signatures = loadHashmapE(cell_r1, tr1, 16, loadCryptoSignaturePair);
  //     data.recover_create_msg = loadMaybeRef(cell_r1, tr1, loadInMsg);
  //     data.mint_msg = loadMaybeRef(cell_r1, tr1, loadInMsg);
  //   }

  //   if (data.key_block)
  if (!keyBlock) {
    // throw Error("not a McBlockExtra");
    console.log("not a KeyBlock");
    return null;
  }

  // // t.cs = 2;
  // const configParams = loadConfigParams(custom, t);
  // console.log('config_addr:', Buffer.from(configParams.config_addr).toString('hex'));
  // console.log(loadConfigParams(custom, t));
  // path.push(custom.refs[3]);

  // _ config_addr:bits256 config:^(Hashmap 32 ^Cell)
  //   = ConfigParams;
  const config = custom.refs[custom.refs.length - 1];
  // path.push(config);

  let hash34 = null;
  loadHashmap(
    config,
    { cs: 0, ref: 0 },
    32,
    (
      c2: TonRocks.types.Cell,
      p2: { cs: number; ref: number },
      n: BN
      // ) =>
      //   console.log({c2,p2,n})
    ) =>
      loadRefIfExist(
        c2,
        p2,
        // (c3, p3) => loadConfigParam(c3, p3, n.toNumber()))));
        (c3: TonRocks.types.Cell, p3: { cs: number; ref: number }) => {
          if (n.toNumber() == 34) {
            hash34 = Buffer.from(c3.getHash()).toString("hex");
            // console.log(n.toString(16), n.toString(10), hash34);
          }
        }
      )
  );

  if (!hash34) {
    // throw Error("not a McBlockExtra");
    console.log("param 34 not found");
    return null;
  }

  const p = buildPath(hash34, config);
  // path.push(p);
  // path.concat(p);
  // console.log(path);
  // console.log('path to config builded');
  // return path;
  return path.concat(p);
};

export const buildValidatorsData = async (root: TonRocks.types.Cell, fileHash: string) => {
  const p = buildPathToConfig(root);
  if (!p) {
    console.log("ups!");
    return;
  }

  // printPath(p);

  const proof = await buildProof(p, true);
  proof.refs[0] = await buildProof([root.refs[0]]);
  await proof.finalizeTree();

  const parts: ISubTree[] = [];
  const { volume } = printTreeVolume(proof, parts);

  console.log("volume:", volume);
  // console.log('parts:', parts);

  const partsIndex = parts.reduce((m, p) => {
    const i = Buffer.from(p.root.getHash()).toString("hex");
    m[i] = p;
    return m;
  }, <Record<string, TonRocks.types.Cell>>{});
  const keysPartsIndex = _.keys(partsIndex);
  console.log("partsIndex:", keysPartsIndex);

  // const buildBoc = async (root: TonRocks.types.Cell) => {
  //   // const tree = await cloneTree(root);
  //   const tree = root;
  //   // await tree.finalize();
  //   return tree.toBoc(false);
  // };

  for (let i = 0; i < parts.length; i++) {
    const leafBoc = await makeBocLeaf(parts[i].root, i, keysPartsIndex);

    // const leafRoot = await checkBoc(leafBoc.toString('hex'));
    // // parse hashmap
    // // data.list = loadHashmap(cell, t, 16, loadValidatorDescr);
    // const t = { cs:0, ref:0 };

    // const dimention = 5;

    // const h = loadHashmap(leafRoot, t, dimention, loadValidatorDescr)
    // for(const { weight, public_key } of h.map.values()) {
    //   const pubKey = Buffer.from(public_key.pubkey);
    //   console.log(pubKey.toString('hex'));
    //   // const bufNodeIdShort = await compute_node_id_short(pubKey);
    //   // res[bufNodeIdShort.toString('hex')] = { weight, pubKey };
    // }
  }
  // await makeBocLeaf(parts[iLeaf].root, iLeaf); iLeaf++;

  const proofPruned = await buildProofExcept(proof, keysPartsIndex);
  await proofPruned.finalizeTree();
  const bocProofPruned = await proofPruned.toBoc(false);

  // const bocConfigParams = await rootConfigParams.toBoc(false);
  console.log("=== begin bocProofPruned ===");
  // console.log('=== begin bocConfigParams ===');
  console.log(Buffer.from(bocProofPruned).toString("hex"));
  // console.log(Buffer.from(bocConfigParams).toString('hex'));
  console.log("=== end bocProofPruned ===");
  // console.log('=== end bocConfigParams ===');

  const cellsProofRoot = await checkBoc(bocProofPruned);
  // const parsedBlock2 = TonRocks.bc.BlockParser.parseBlock(cellsProofRoot);
  // console.log(parsedBlock2.extra.custom.config);

  // // console.log('===', Buffer.from(cellsConfigParams[0].getHash()).toString('hex'), '===');
  // console.log('===', Buffer.from(await cellsConfigParams[0].hash()).toString('hex'), '===');
  console.log("=== file_hash:", fileHash, "===");

  console.log("ROOT BLOCK PARSING:");
  // const parsedBlock = TonRocks.bc.BlockParser.parseBlock(root);
  const parsedBlock = TonRocks.bc.BlockParser.parseBlock(cellsProofRoot);
  console.log("ROOT BLOCK PARSING END");

  // for(const { weight, public_key } of map.values()) {
  //   const pubKey = Buffer.from(public_key.pubkey);
  //   const bufNodeIdShort = await compute_node_id_short(pubKey);
  //   res[bufNodeIdShort.toString('hex')] = { weight, pubKey };
  // }
  const curValidators = parsedBlock.extra.custom.config.config.map.get("22");
  if (!curValidators) {
    throw new Error("xxx");
  }
  for (const { public_key } of curValidators.cur_validators.list.map.values()) {
    const pubKey = Buffer.from(public_key.pubkey);
    console.log(pubKey.toString("hex"));
  }

  return parsedBlock;
};
