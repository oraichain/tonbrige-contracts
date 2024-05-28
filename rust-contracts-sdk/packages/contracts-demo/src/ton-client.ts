import { getHttpEndpoint } from "@orbs-network/ton-access";
import { mnemonicToWalletKey } from "@ton/crypto";
import { TonClient, WalletContractV4, internal } from "@ton/ton";
import "dotenv/config";

(async () => {
  const endpoint = await getHttpEndpoint({ network: "mainnet" });
  // Create Client
  const client = new TonClient({
    endpoint
  });

  // Generate new key
  const mnemonic = process.env.TON_MNEMONIC.split(" ");
  const keyPair = await mnemonicToWalletKey(mnemonic);

  // Create wallet contract
  let workchain = 0; // Usually you need a workchain 0
  let wallet = WalletContractV4.create({ workchain, publicKey: keyPair.publicKey });
  let contract = client.open(wallet);

  const tonClient = new TonClient({ endpoint });

  // Get balance
  let balance: bigint = await contract.getBalance();
  console.log("balance: ", balance.toString());

  // Create a transfer
  let seqno: number = await contract.getSeqno();
  const transferCell = contract.createTransfer({
    seqno,
    secretKey: keyPair.secretKey,
    messages: [
      internal({
        value: "1.5",
        to: "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N",
        body: "Hello world"
      })
    ]
  });

  const masterchainInfo = await tonClient.getMasterchainInfo();
  console.log("last block: ", masterchainInfo);
})();
