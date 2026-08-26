// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";
import {RiscZeroMockVerifier} from "risc0-risc0-ethereum-3.0.0/test/RiscZeroMockVerifier.sol";

/// @dev Prefer DeployAuthenticityVerifier.s.sol. Kept as a short alias.
contract DeployVerifierScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address riscZeroVerifierAddress = vm.envOr("RISC_ZERO_VERIFIER_ADDRESS", address(0));
        bytes32 imageId = vm.envBytes32("ZK_PROVER_GUEST_ID");
        bytes32 expectedAlg = vm.envOr("EXPECTED_ALG", bytes32("sha256+gradient-phash-v1"));

        vm.startBroadcast(deployerPrivateKey);

        address verifierAddress = riscZeroVerifierAddress;
        if (verifierAddress == address(0)) {
            RiscZeroMockVerifier mockVerifier = new RiscZeroMockVerifier(bytes4(0xffffffff));
            verifierAddress = address(mockVerifier);
            console.log("RiscZeroMockVerifier", verifierAddress);
        }

        AuthenticityVerifier auth = new AuthenticityVerifier(verifierAddress, imageId, expectedAlg);
        console.log("AuthenticityVerifier", address(auth));

        vm.stopBroadcast();
    }
}
