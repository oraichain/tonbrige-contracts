pragma solidity 0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract BitReaderTest is Test {
    

    function setUp() public {
        
    }

    function test_bytes32() public {
        uint256 testNumber = 42;
        bytes32 ret = bytes32(testNumber);
        console.logBytes32(ret);
    }

   
}