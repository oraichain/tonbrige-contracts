import { TonbridgeValidatorInterface } from "@oraichain/tonbridge-contracts-sdk";
import { UserFriendlyValidator } from "@oraichain/tonbridge-contracts-sdk/build/TonbridgeValidator.types";

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
