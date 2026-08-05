// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "risc0-risc0-ethereum-3.0.0/IRiscZeroVerifier.sol";

// Verifies authenticity receipts: seal + ABI journal against IMAGE_ID.
contract AuthenticityVerifier {
    IRiscZeroVerifier public immutable VERIFIER;
    bytes32 public immutable IMAGE_ID;
    bytes32 public immutable EXPECTED_ALG;
    uint32 public constant EXPECTED_THRESHOLD = 5;

    struct VerifiedClaim {
        bytes32 imageSha256;
        bytes32 phash0;
        bytes32 phash1;
        bytes32 devicePubkey;
        uint32 distance;
        uint32 threshold;
        bytes32 alg;
        bool verified;
    }

    mapping(bytes32 => VerifiedClaim) public claimsByJournalDigest;

    event AuthenticityVerified(
        bytes32 indexed journalDigest,
        bytes32 imageSha256,
        bytes32 phash0,
        bytes32 phash1,
        bytes32 devicePubkey,
        uint32 distance,
        uint32 threshold,
        bytes32 alg
    );

    error BadJournalLength();
    error BadThreshold();
    error DistanceTooLarge();
    error BadAlg();
    error ZKProofVerificationFailed();

    constructor(address verifier, bytes32 imageId, bytes32 expectedAlg) {
        VERIFIER = IRiscZeroVerifier(verifier);
        IMAGE_ID = imageId;
        EXPECTED_ALG = expectedAlg;
    }

    // journalData is abi.encode of sha256, phash0, phash1, pubkey, distance, threshold, alg.
    function verifyAuthenticity(bytes calldata seal, bytes calldata journalData) external {
        if (journalData.length != 32 * 7) {
            revert BadJournalLength();
        }

        (
            bytes32 imageSha256,
            bytes32 phash0,
            bytes32 phash1,
            bytes32 devicePubkey,
            uint32 distance,
            uint32 threshold,
            bytes32 alg
        ) = abi.decode(
            journalData,
            (bytes32, bytes32, bytes32, bytes32, uint32, uint32, bytes32)
        );

        if (threshold != EXPECTED_THRESHOLD) {
            revert BadThreshold();
        }
        if (distance > threshold) {
            revert DistanceTooLarge();
        }
        if (alg != EXPECTED_ALG) {
            revert BadAlg();
        }

        bytes32 journalDigest = sha256(journalData);
        try VERIFIER.verify(seal, IMAGE_ID, journalDigest) {} catch {
            revert ZKProofVerificationFailed();
        }

        claimsByJournalDigest[journalDigest] = VerifiedClaim({
            imageSha256: imageSha256,
            phash0: phash0,
            phash1: phash1,
            devicePubkey: devicePubkey,
            distance: distance,
            threshold: threshold,
            alg: alg,
            verified: true
        });

        emit AuthenticityVerified(
            journalDigest,
            imageSha256,
            phash0,
            phash1,
            devicePubkey,
            distance,
            threshold,
            alg
        );
    }
}
