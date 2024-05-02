pragma solidity 0.8.15;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../libraries/Ed25519.sol";

bytes constant ED25519_MESSAGE_HEX = hex"af82";
bytes32 constant ED25519_SIGNATURE_R_HEX = 0x6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac;
bytes32 constant ED25519_SIGNATURE_S_HEX = 0x18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a;
bytes32 constant ED25519_PUBLIC_KEY_HEX = 0xfc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025;

contract SignatureValidatorTest is Test {
    function setUp() public {}

    // forge test --match-test test_verify_signature -vv
    function test_verify_signature() public view {
        bool ret = Ed25519.verify(
            ED25519_PUBLIC_KEY_HEX,
            ED25519_SIGNATURE_R_HEX,
            ED25519_SIGNATURE_S_HEX,
            ED25519_MESSAGE_HEX
        );
        console.logBool(ret);
    }
}
