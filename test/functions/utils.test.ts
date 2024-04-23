import { ethers } from "hardhat";
import { data } from "../data/transaction-1";
import { BitReader__factory } from "../../typechain";

describe("test utils function", () => {
  it("test parser", async () => {
    const [signer] = await ethers.getSigners();
    const bitReader = await new BitReader__factory(signer).deploy();

    const boc = Buffer.from(
      data.find((el) => el.type === "state-hash")!.boc[0],
      "hex"
    );

    console.log(boc);
  });
});
