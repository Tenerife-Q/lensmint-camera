// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Old notary-style verifier. Use AuthenticityVerifier instead.
contract LensMintVerifier {
    error DeprecatedUseAuthenticityVerifier();

    constructor() {
        revert DeprecatedUseAuthenticityVerifier();
    }
}
