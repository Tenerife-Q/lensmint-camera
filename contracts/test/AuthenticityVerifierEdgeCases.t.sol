// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";
import {IRiscZeroVerifier, Receipt as RiscZeroReceipt} from "risc0-risc0-ethereum-3.0.0/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "risc0-risc0-ethereum-3.0.0/test/RiscZeroMockVerifier.sol";

contract AuthenticityVerifierEdgeCasesTest is Test {
    bytes4 internal constant MOCK_SELECTOR = bytes4(0xffffffff);
    bytes32 internal constant IMAGE_ID = bytes32(uint256(0xA11CE));
    bytes32 internal constant ALG = bytes32("sha256+gradient-phash-v1");

    RiscZeroMockVerifier internal mock;
    AuthenticityVerifier internal auth;

    function setUp() public {
        mock = new RiscZeroMockVerifier(MOCK_SELECTOR);
        auth = new AuthenticityVerifier(address(mock), IMAGE_ID, ALG);
    }

    function _journal(uint32 distance, uint32 threshold, bytes32 alg) internal pure returns (bytes memory) {
        return abi.encode(
            bytes32(uint256(0x1111)),
            bytes32(bytes8(0x0d1a34489032468c)),
            bytes32(bytes8(0x0d1a34489032468d)),
            bytes32(uint256(0x2222)),
            distance,
            threshold,
            alg
        );
    }

    function _mockSeal(bytes32 imageId, bytes memory journal) internal view returns (bytes memory) {
        RiscZeroReceipt memory receipt = mock.mockProve(imageId, sha256(journal));
        return receipt.seal;
    }

    function test_bad_journal_length_reverts() public {
        vm.expectRevert(AuthenticityVerifier.BadJournalLength.selector);
        auth.verifyAuthenticity("", new bytes(223));

        vm.expectRevert(AuthenticityVerifier.BadJournalLength.selector);
        auth.verifyAuthenticity("", new bytes(225));
    }

    function test_bad_algorithm_reverts() public {
        bytes memory journal = _journal(1, 5, bytes32("wrong-alg"));
        bytes memory seal = _mockSeal(IMAGE_ID, journal);

        vm.expectRevert(AuthenticityVerifier.BadAlg.selector);
        auth.verifyAuthenticity(seal, journal);
    }

    function test_distance_at_threshold_succeeds() public {
        bytes memory journal = _journal(5, 5, ALG);
        bytes memory seal = _mockSeal(IMAGE_ID, journal);

        auth.verifyAuthenticity(seal, journal);

        bytes32 digest = sha256(journal);
        (,,,, uint32 storedDistance, uint32 storedThreshold,, bool verified) = auth.claimsByJournalDigest(digest);
        assertEq(storedDistance, 5);
        assertEq(storedThreshold, 5);
        assertTrue(verified);
    }

    function test_distance_over_threshold_reverts() public {
        bytes memory journal = _journal(6, 5, ALG);
        bytes memory seal = _mockSeal(IMAGE_ID, journal);

        vm.expectRevert(AuthenticityVerifier.DistanceTooLarge.selector);
        auth.verifyAuthenticity(seal, journal);
    }

    function test_wrong_image_id_seal_reverts() public {
        bytes memory journal = _journal(1, 5, ALG);
        bytes memory seal = _mockSeal(bytes32(uint256(0xB0B)), journal);

        vm.expectRevert(AuthenticityVerifier.ZKProofVerificationFailed.selector);
        auth.verifyAuthenticity(seal, journal);
    }

    function test_verifier_receives_image_id_and_journal_digest() public {
        bytes memory journal = _journal(1, 5, ALG);
        bytes memory seal = _mockSeal(IMAGE_ID, journal);

        vm.expectCall(address(mock), abi.encodeCall(IRiscZeroVerifier.verify, (seal, IMAGE_ID, sha256(journal))));
        auth.verifyAuthenticity(seal, journal);
    }
}
