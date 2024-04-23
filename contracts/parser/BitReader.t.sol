pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "./BitReader.sol";

contract BitReaderTest is Test {

    BitReader bitReader;
    
    function setUp() public {
        bitReader = new BitReader();
    }

    function test_bytes32() public {
        uint256 testNumber = 100_000_042;
        bytes32 ret = bytes32(testNumber);
        console.logBytes32(ret);
    }


    function test_log2Ceil() public {
        uint256 testNumber = 1_000_000_042;
        for (uint256 i = 0; i < 100; i++) {
            uint256 ret = bitReader.log2Ceil(testNumber + i*10_000_000_000);
            console.log("ret %i",ret);
        }
    }
   
}