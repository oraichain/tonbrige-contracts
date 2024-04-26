pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./parser/TreeOfCellsParser.sol";
import "./types/BagOfCellsInfo.sol";
import "./types/CellData.sol";


bytes constant MASTER_PROOF = hex"b5ee9c72c102070100011500000e0034005a00a300c900ef0115241011ef55aafffffffd010203062848010157d5d40d6835fb10eab860add2c9ed9384007cbd5c4af7006716f5eeb6109092000128480101c3b6883898411dde154d6b1040de039f6adcb180ce452ba14459b202a7be8bd600030a8a045525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e36184f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f001f0405284801015525d791b3de6fc915dbde3bf1dd45a64fa57385bdf5ef1696978e86c92e3618001f284801014f47e6ab2643a05202e78a2c8723bd99edbad0dd162d21440b820943de7e9ae7001f284801011ca3e8075b0f29141deae260b25832844ffdaea9e42d41e9c62f0bf875a132d800075572e271";


contract TransactionParserTest is Test {

    TreeOfCellsParser treeOfCellsParser;
    

    function setUp() public {
        treeOfCellsParser = new TreeOfCellsParser();
        
    }

    function test_masterProof() public {
        
        BagOfCellsInfo memory header = treeOfCellsParser.parseSerializedHeader(MASTER_PROOF);
    
        CellData[100] memory toc = treeOfCellsParser.get_tree_of_cells(MASTER_PROOF, header);

        console.log(header.rootIdx);        
        console.logBool(toc[0].special);
        
    }
   
}

