// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/** The process of verifying a signature using solidity has 4 steps
 * hash(message)
 * sign(hash(message),privateKey) | this is done offchain  
 * ecrecover(hash(message),signature) == signer
 */

contract VerifySig {
    /**
     * This is the function that is used to verify the signature
     * @param _signer the address of the signer
     * @param _message the message
     * @param _sig the signature
     * @return true if the signature is valid, false otherwise
     */
    function verify(
        address _signer,
        string memory _message,
        bytes memory _sig
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(_message);

        // The message that is signed offchain is not just message hash
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recover(ethSignedMessageHash, _sig) == _signer;
    }

    function getMessageHash(
        string memory _message
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_message));
    }

    /**
     * when a message is sent from offchain to onchain first the message is signed then the 
     * hash of the message is prefixed with ("\x19Ethereum Signed Message:\n32") and then re-hashed
     * we can see that "\n32" is the size of the message that is hashed and all this is done offchain by the wallet
     * @param _ethMsgHash the hash of the message
     */
    function getEthSignedMessageHash(
        bytes32 _ethMsgHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    _ethMsgHash
                )
            );
    }
}
