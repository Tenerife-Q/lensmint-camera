// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";
import {RiscZeroMockVerifier} from "risc0-risc0-ethereum-3.0.0/test/RiscZeroMockVerifier.sol";

contract DeployAuthenticityVerifierScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address riscZeroVerifier = vm.envOr("RISC_ZERO_VERIFIER_ADDRESS", address(0));
        bytes32 imageId = vm.envBytes32("ZK_PROVER_GUEST_ID");
        bytes32 expectedAlg = vm.envOr(
            "EXPECTED_ALG",
            bytes32("sha256+gradient-phash-v1")
        );

        vm.startBroadcast(deployerPrivateKey);

        address verifierAddr = riscZeroVerifier;
        if (verifierAddr == address(0)) {
            RiscZeroMockVerifier mock = new RiscZeroMockVerifier(bytes4(0xffffffff));
            verifierAddr = address(mock);
            console.log("Deployed RiscZeroMockVerifier", verifierAddr);
        } else {
            console.log("Using RISC Zero verifier", verifierAddr);
        }

        AuthenticityVerifier auth = new AuthenticityVerifier(verifierAddr, imageId, expectedAlg);
        console.log("AuthenticityVerifier", address(auth));
        console.logBytes32(imageId);
        console.logBytes32(expectedAlg);

        vm.stopBroadcast();
    }
}
