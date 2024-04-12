// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.18;

import {Test} from "forge-std/Test.sol";
import {VerifySig} from "../src/Sig.sol";
import "forge-std/console.sol";

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
        address pubkey = vm.addr(privateKey); // -> x
        address wrongPubKey = address(52637); // -> y

        string memory message = "hello world";

        bytes32 messagehash = keccak256("hello world");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messagehash); // message signature

        bytes memory signature = abi.encodePacked(r, s, v); // bytes concatenation of v,r,s

        address signer = ecrecover(messagehash, v, r, s);
        
        assertEq(pubkey, signer); // assert that the signer is the same as the public key
        vm.expectRevert(); // it was expected to revert to test will not fail, else it will fail
        assert(wrongPubKey == signer); // assert that the signer is not the same as the wrong public key

        console.log("The private Key is                    :  " , privateKey);
        console.log("The Public key from above private key :  " , pubkey);
        console.log("The message is                        :  " , message);
        // console.log("The message hash is                   :  " , messagehash);
        console.log("The signature, part v is              :  " , v);
        // console.log("The signature, part r is              :  " , r);
        // console.log("The signature, part s is              :  " , s);
        // console.log("The signature is                      :  " , signature);
        // console.log("The signer is                         :  " , signer);

        // bool x = verificationContract.verify(pubkey,"hello world",signature);
        // assert(x == true);
    }

    // function testSignatureVerifyContract() public {
    //     uint256 privateKey = 123;
    //     address pubkey = vm.addr(privateKey);

    //     bytes32 messagehash = keccak256("hello world");

    //     bytes32 ethsignedmessage = verificationContract.getEthSignedMessageHash(messagehash);

    // }
}
