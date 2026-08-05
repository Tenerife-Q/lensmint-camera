// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";
import {RiscZeroMockVerifier} from "risc0-risc0-ethereum-3.0.0/test/RiscZeroMockVerifier.sol";

contract DeployLensMintVerifierScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes32 imageId = vm.envBytes32("ZK_PROVER_GUEST_ID");
        bytes32 expectedAlg = vm.envOr("EXPECTED_ALG", bytes32("sha256+gradient-phash-v1"));

        vm.startBroadcast(deployerPrivateKey);
        RiscZeroMockVerifier mockVerifier = new RiscZeroMockVerifier(bytes4(0xffffffff));
        AuthenticityVerifier auth =
            new AuthenticityVerifier(address(mockVerifier), imageId, expectedAlg);
        console.log("RiscZeroMockVerifier", address(mockVerifier));
        console.log("AuthenticityVerifier", address(auth));
        vm.stopBroadcast();
    }
}
