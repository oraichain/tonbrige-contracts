import { TonbridgeValidatorInterface } from "@oraichain/tonbridge-contracts-sdk";
import { UserFriendlyValidator } from "@oraichain/tonbridge-contracts-sdk/build/TonbridgeValidator.types";
import { ParsedBlock } from "@oraichain/tonbridge-utils";
import { LiteClient, LiteEngine } from "ton-lite-client";
import { Functions } from "ton-lite-client/dist/schema";
import { parseBlock } from "../build/common";

export const queryAllValidators = async (tonValidator: TonbridgeValidatorInterface) => {
  let validators: UserFriendlyValidator[] = [];
  let startAfter = 0;

  while (true) {
    const validatorsTemp = await tonValidator.getValidators({ limit: 30, startAfter, order: 0 });
    if (validatorsTemp.length === 0) {
      break;
    }
    validators = validators.concat(validatorsTemp);
    startAfter = validators.length;
  }
  return validators;
};

export const queryAllValidatorCandidates = async (tonValidator: TonbridgeValidatorInterface) => {
  let candidates: UserFriendlyValidator[] = [];
  let startAfter = 0;

  while (true) {
    const candidatesTemp = await tonValidator.getCandidatesForValidators({ limit: 30, startAfter, order: 0 });
    if (candidatesTemp.length === 0) {
      break;
    }
    candidates = candidates.concat(candidatesTemp);
    startAfter = candidates.length;
  }
  return candidates;
};

export const queryKeyBlock = async (client: LiteClient, engine: LiteEngine, masterChainSeqNo: number) => {
  let initBlockSeqno = masterChainSeqNo;
  while (true) {
    const fullBlock = await client.getFullBlock(initBlockSeqno);
    const initialBlockInformation = fullBlock.shards.find((blockRes) => blockRes.seqno === initBlockSeqno);
    // get block
    const block = await engine.query(Functions.liteServer_getBlock, {
      kind: "liteServer.getBlock",
      id: {
        kind: "tonNode.blockIdExt",
        ...initialBlockInformation
      }
    });

    const parsedBlock: ParsedBlock = await parseBlock(block);
    if (!parsedBlock.info.key_block) {
      initBlockSeqno = parsedBlock.info.prev_key_block_seqno;
      continue;
    }
    return { parsedBlock, rawBlockData: block, initialKeyBlockInformation: initialBlockInformation };
  }
};
