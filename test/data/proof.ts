const boc1 =
  "b5ee9c72c102210100045d000034005a008000a600d700fd01230187019501bb01c901ef01fc0222022f025502620288029502bb02c802ee02fb0321032e035403610387039403ba04110437045d245b9023afe2fffffffd00ffffffff00000000000000000042657a000000006356788d000004d289c48144004265766001020304284801012e3630052148fa0b45032bbf56c4cdb7f75fdb858b7209e812d522c01e50839b0001284801012fe000db45bd7b88d1bfaa39712117c48b2904a8c68c599788f7e5cd833c2552001e28480101e09b3c10e1225a724a0ef5ce2abfa737ff4123206b205f2ade0f2f63279ebc8300022455cc26aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac22c820575fe88ac0605060720284801010666deecfa1acfbc94475de8dbbf957379564f49b15f194f181f3f1133391fc0000228480101f1be0292cfdca524014dd94f6bf23eec42dd3ec8fd2f434bd863c09c1f33b88b001022bf00011378da3a0000dfa76000009a5136a7e088000026921ce74820021312194976d896d6d8dab6dae22343df8988ee561c044fc5c4ad88df8647deb02cc4f6fe9e07932f3179a065c0105051dae8281eb8e5426afa0591b9742c0a3e01dd08be081f2213c4c0000134a26d4fc120090a28480101d42c99de12dc1e15852be5a9bde63ab92d2499ceb5c5aed9748a51dd77f9561a00162213c48000026944da9f82400b0c284801012cfbf547cdabdb702b62572a205549fab580b8ffaea09abc3be39236f312755b0011221162000009a5136a7e090d0e28480101732106091c22be0636949f8ff10767694c16a183ea6cc1f982df10e701bd61bb000e22112000009a5136a7e0900f1028480101a98146cba3b627c3ccbe3e00645192311e4ed2e77f0b1fcbcd3f0cdf89510193000d221162000009a5136a7e091112284801017e94f657bf7789ca627f1271bb286f3d6cde7628c66dfb56d40d7644044dd291000a221140000026944da9f82413142848010131a1012ebe92010a6a9c24b75f7fe0f8045b989e632db6cebbf3de6979a410420008221140000026944da9f82415162848010138920fbae48b9aab2e113ebd24c368c66677268645f2a8f7f28ec60deb0d6b5a000622110000009a5136a7e090171828480101e167ecd91aee7d64fb63b53655c236c816282737a748ef684742d975cb2b0649000522110000009a5136a7e090191a2848010127ccfabbebe7fce579b370830459070fad5641e8a0dad36d289bc6f605b74149000422110000009a5136a7e0901b1c2848010166beee42468453c91cb98515255e07b917494ad972d14851264f385d07eddf4900032211d00000134a26d4fc121d1e284801013e1ffe694f8302aef6a7545fe6901055c4b153f5a574414ce73953d2df0072db000000a90000009a5136a7e08000004d289b53f0400426579ef2b87352875737c44346b7588cb799b6ca7c10e47015515026f035fe8b6a5c7f7d00fa09045390aa8d4cbd1cff7501e997d7c62ab6d6003ad58f78b010a6d80828480101a0af1529c7d1ae7d7ca8ad4fceb8d06baaaa47cd2a79194de7961adc03889428000f28480101b20e36a3b36a4cdee601106c642e90718b0a58daf200753dbb3189f956b494b60001803269ac";

export const bocProofState = Buffer.from(boc1, "hex");

// seq_no 4351353 426579
// end_lt 5302300000004 4d289b53f04
// root_hash ef2b87352875737c44346b7588cb799b6ca7c10e47015515026f035fe8b6a5c7

const boc2 =
  "b5ee9c72c102070100011500000e0034005a00a300c900ef0115241011ef55aafffffffd010203062848010157d5d40d6835fb10eab860add2c9ed9384007cbd5c4af7006716f5eeb6109092000128480101c3b6883898411dde154d6b1040de039f6adcb180ce452ba14459b202a7be8bd600030a8a045525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e36184f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f001f0405284801015525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e3618001f284801014f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f284801011ca3e8075b0f29141deae260b25832844ffdaea9e42d41e9c62f0bf875a132d800075572e271";

export const masterProof = Buffer.from(boc2, "hex");

// new_hash: 4f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7
// 0DB46601B142520443DDD6AD6E61CF280C3FBDCAF25032F430176FA85C015C74