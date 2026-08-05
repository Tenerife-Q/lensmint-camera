// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";

contract SubmitProofScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address authAddr = vm.envAddress("AUTHENTICITY_VERIFIER_ADDRESS");
        string memory sealPath = vm.envString("SEAL_FILE");
        string memory journalPath = vm.envString("JOURNAL_ABI_FILE");

        bytes memory seal = vm.readFileBinary(sealPath);
        bytes memory journal = vm.readFileBinary(journalPath);

        vm.startBroadcast(deployerPrivateKey);
        AuthenticityVerifier(authAddr).verifyAuthenticity(seal, journal);
        vm.stopBroadcast();
        console.log("submit complete");
    }
}
