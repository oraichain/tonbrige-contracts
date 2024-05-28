export interface ParsedBlock {
  global_id: number;
  info: {
    version: number;
    key_block: boolean;
    seq_no: number;
    prev_seq_no: number;
    gen_utime: number;
    prev_key_block_seqno: number;
    start_lt: BigInt;
    end_lt: BigInt;
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
