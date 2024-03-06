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
     * @notice
     * when a message is sent from offchain to onchain first the message is signed then the
     * hash of the message is prefixed with ("\x19Ethereum Signed Message:\n32") and then re-hashed
     * we can see that "\n32" is the size of the message in bytes that is hashed and all this is
     * done offchain by the wallet. This is the actual message that is signed offchain
     * @param _ethMsgHash the hash of the message
     */
    function getEthSignedMessageHash(
        bytes32 _ethMsgHash
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    _ethMsgHash
                )
            );
    }

    /**
     *
     * @param ethSignedMessageHash The actual signed message offchain
     * @param sig the signature that is sent from offchain
     */
    function recover(
        bytes32 ethSignedMessageHash,
        bytes memory sig
    ) public pure returns (address) {
        // the r and s that are returned are cryptographic values that are needed in digital signatures
        // the parameter v is something that is for ethereum
        (bytes32 r, bytes32 s, uint8 v) = split(sig);

        // the ecrecover function takes the ethSignedMessageHash as input which includes "\x19Ethereum Signed Message:\n32"
        //  and takes the cryptographic values that will be used to verify the signature
        // and it returns the address of the caller who created the signature
        // the ecrecover() function is inbuilt in solidity
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    /**
     * @notice here point to remember that _sig is not the signature but its the address of the location
     * where the signature is stored in memory (pointer) since its a dynamic sized input so remember that 
     * the first 32 bytes will have the lemgth of the data 
     * 
     * @param _sig here the sig is the signature that is passed  
     * @return r the cryptographic value
     * @return s the cryptographic value
     * @return v the value need for ethereum 
     */
    function split(
        bytes memory _sig
    ) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(_sig.length == 65, "Invalid signature length");
        assembly {
            // since mentioned above we know that the _sig passed as parameter is the pointer to the 
            // location in memory where the value is stored and the first 32 bytes is the length of the 
            // data so we skip it by adding 32bytes to the start position of sig in memory
            // the first 32bytes after skipping the length is the r value which is a bytes32 type value
            r := mload(add(_sig, 32))

            // then to get the place of the next 32 bytes we need to skip both the length of data and the 
            // value of r that is stored in memory  so we add 32+32=64
            s := mload(add(_sig, 64))


            v := byte(0, mload(add(_sig, 96)))

        }
    }

}
