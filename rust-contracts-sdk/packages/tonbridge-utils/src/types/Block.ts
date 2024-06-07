import { HashmapAugE } from "./Hashmap";

// FIXME: add remaining types
export interface ParsedBlock {
  global_id: number;
  info: {
    version: number;
    not_master: number;
    after_merge: number;
    before_split: number;
    after_split: number;
    want_split: number;
    want_merge: number;
    key_block: boolean;
    vert_seqno_incr: number;
    flags: number;
    seq_no: number;
    vert_seq_no: number;
    prev_seq_no: number;
    gen_utime: number;
    prev_key_block_seqno: number;
    gen_validator_list_hash_short: number;
    gen_catchain_seqno: number;
    min_ref_mc_seqno: number;
    start_lt: BigInt;
    end_lt: BigInt;
  };
  extra?: {
    account_blocks: HashmapAugE;
    custom?: {
      config?: {
        config?: {
          map: Map<string, any>;
        };
      };
    };
  };
}
