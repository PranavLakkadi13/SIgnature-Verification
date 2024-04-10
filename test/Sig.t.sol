// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.18;

import {Test} from "forge-std/Test.sol";
import {VerifySig} from "../src/Sig.sol";

contract TestSign is Test {
    /**
     * private key = 123
     * pubkey = vm.addr(privateKey);
     * message = "hello world"
     * message hash = keccak256(message)
     * vm.sign(privateKey, message hash);
     */

    VerifySig public verificationContract;

    function setUp() public {
        verificationContract = new VerifySig();
    }

    function testSignature() public {
        uint256 privateKey = 123;
        address pubkey = vm.addr(privateKey);
        address z = address(52637);

        bytes32 messagehash = keccak256("hello world");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messagehash);

        address signer = ecrecover(messagehash, v, r, s);
        
        assertEq(pubkey, signer);
        // assert(z == signer);

        // bool x = verificationContract.verify(pubkey,"hello world");
    }

    function testSignatureVerifyContract() public {
        uint256 privateKey = 123;
        address pubkey = vm.addr(privateKey);

        bytes32 messagehash = keccak256("hello world");

        bytes32 ethsignedmessage = verificationContract.getEthSignedMessageHash(messagehash);

    }
}
