pragma solidity 0.8.15;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract TransactionParserTest is Test {
    function setUp() public {}

    function test_address() public {
        uint256 testNumber = 1_000_000_042;
        address addr = address(uint160(testNumber));

        console.logAddress(addr);
    }
}
