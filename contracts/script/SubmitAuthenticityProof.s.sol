// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";

// Submit seal + ABI journal. Paths are relative to the contracts/ project root.
contract SubmitAuthenticityProofScript is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address authAddr = vm.envAddress("AUTHENTICITY_VERIFIER_ADDRESS");
        string memory sealPath = vm.envString("SEAL_FILE");
        string memory journalPath = vm.envString("JOURNAL_ABI_FILE");

        bytes memory seal = vm.readFileBinary(sealPath);
        bytes memory journal = vm.readFileBinary(journalPath);

        console.log("AuthenticityVerifier", authAddr);
        console.log("seal bytes", seal.length);
        console.log("journal bytes", journal.length);

        vm.startBroadcast(pk);
        AuthenticityVerifier(authAddr).verifyAuthenticity(seal, journal);
        vm.stopBroadcast();

        console.log("verifyAuthenticity submitted");
    }
}
