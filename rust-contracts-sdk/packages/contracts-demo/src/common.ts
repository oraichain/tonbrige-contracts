import TonRocks, { ParsedBlock } from "@oraichain/tonbridge-utils";
import { liteServer_BlockData } from "ton-lite-client/dist/schema";

export function intToIP(int: number) {
  var part1 = int & 255;
  var part2 = (int >> 8) & 255;
  var part3 = (int >> 16) & 255;
  var part4 = (int >> 24) & 255;

  return part4 + "." + part3 + "." + part2 + "." + part1;
}

export async function parseBlock(block: liteServer_BlockData): Promise<ParsedBlock> {
  const [rootCell] = await TonRocks.types.Cell.fromBoc(block.data.toString("hex"));

  // Additional check for rootHash
  const rootHash = Buffer.from(rootCell.hashes[0]).toString("hex");
  if (rootHash !== block.id.rootHash.toString("hex")) {
    throw Error("got wrong block or here was a wrong root_hash format");
  }

  const parsedBlock = TonRocks.bc.BlockParser.parseBlock(rootCell);
  return parsedBlock;
}
