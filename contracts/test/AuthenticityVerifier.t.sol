// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthenticityVerifier} from "../src/AuthenticityVerifier.sol";
import {Receipt as RiscZeroReceipt} from "risc0-risc0-ethereum-3.0.0/IRiscZeroVerifier.sol";
import {RiscZeroMockVerifier} from "risc0-risc0-ethereum-3.0.0/test/RiscZeroMockVerifier.sol";

contract AuthenticityVerifierTest is Test {
    bytes4 internal constant MOCK_SELECTOR = bytes4(0xffffffff);
    bytes32 internal constant IMAGE_ID = bytes32(uint256(0xA11CE));
    // Left-aligned ASCII for sha256+gradient-phash-v1
    bytes32 internal constant ALG = bytes32("sha256+gradient-phash-v1");

    RiscZeroMockVerifier internal mock;
    AuthenticityVerifier internal auth;

    function setUp() public {
        mock = new RiscZeroMockVerifier(MOCK_SELECTOR);
        auth = new AuthenticityVerifier(address(mock), IMAGE_ID, ALG);
    }

    function _journal(
        bytes32 sha256Hash,
        bytes32 phash0,
        bytes32 phash1,
        bytes32 pubkey,
        uint32 distance,
        uint32 threshold,
        bytes32 alg
    ) internal pure returns (bytes memory) {
        return abi.encode(sha256Hash, phash0, phash1, pubkey, distance, threshold, alg);
    }

    function _mockSeal(bytes memory journal) internal view returns (bytes memory) {
        RiscZeroReceipt memory receipt = mock.mockProve(IMAGE_ID, sha256(journal));
        return receipt.seal;
    }

    function test_verify_success() public {
        bytes32 sha256Hash = bytes32(uint256(0x1111));
        bytes32 phash0 = bytes32(bytes8(0x0d1a34489032468c));
        bytes32 phash1 = bytes32(bytes8(0x0d1a34489032468c));
        bytes32 pubkey = bytes32(uint256(0x2222));
        bytes memory journal = _journal(sha256Hash, phash0, phash1, pubkey, 0, 5, ALG);
        bytes memory seal = _mockSeal(journal);

        auth.verifyAuthenticity(seal, journal);

        bytes32 digest = sha256(journal);
        (
            bytes32 gotSha,
            bytes32 gotP0,
            bytes32 gotP1,
            bytes32 gotPk,
            uint32 distance,
            uint32 threshold,
            bytes32 gotAlg,
            bool verified
        ) = auth.claimsByJournalDigest(digest);

        assertTrue(verified);
        assertEq(gotSha, sha256Hash);
        assertEq(gotP0, phash0);
        assertEq(gotP1, phash1);
        assertEq(gotPk, pubkey);
        assertEq(distance, 0);
        assertEq(threshold, 5);
        assertEq(gotAlg, ALG);
    }

    function test_fake_seal_reverts() public {
        bytes memory journal = _journal(
            bytes32(uint256(1)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(uint256(2)),
            0,
            5,
            ALG
        );
        bytes memory badSeal = abi.encodePacked(MOCK_SELECTOR, bytes32(uint256(0xdead)));

        vm.expectRevert(AuthenticityVerifier.ZKProofVerificationFailed.selector);
        auth.verifyAuthenticity(badSeal, journal);
    }

    function test_wrong_journal_digest_reverts() public {
        bytes memory journal = _journal(
            bytes32(uint256(1)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(uint256(2)),
            0,
            5,
            ALG
        );
        bytes memory seal = _mockSeal(journal);

        bytes memory tampered = _journal(
            bytes32(uint256(999)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(uint256(2)),
            0,
            5,
            ALG
        );

        vm.expectRevert(AuthenticityVerifier.ZKProofVerificationFailed.selector);
        auth.verifyAuthenticity(seal, tampered);
    }

    function test_bad_threshold_reverts() public {
        bytes memory journal = _journal(
            bytes32(uint256(1)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(bytes8(0x0102030405060708)),
            bytes32(uint256(2)),
            0,
            6,
            ALG
        );
        bytes memory seal = _mockSeal(journal);

        vm.expectRevert(AuthenticityVerifier.BadThreshold.selector);
        auth.verifyAuthenticity(seal, journal);
    }

    function test_rust_abi_fixture_matches_solidity() public pure {
        // Same field layout as the Rust ABI journal helper.
        bytes32 sha256Hash = hex"e8e12e6a5f63658efb1766cdec4bd3f56400baf7200f2936710a8027a043676c";
        bytes32 phash0 = bytes32(bytes8(hex"0d1a34489032468c"));
        bytes32 phash1 = bytes32(bytes8(hex"0d1a34489032468c"));
        bytes32 pubkey = hex"1111111111111111111111111111111111111111111111111111111111111111";
        bytes memory journal = _journal(sha256Hash, phash0, phash1, pubkey, 0, 5, ALG);
        assertEq(journal.length, 224);
    }
}
