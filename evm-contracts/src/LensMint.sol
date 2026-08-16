// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract LensMint is ERC721, AccessControl {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 private _nextTokenId;

    struct CameraRecord {
        string uuid;
        bytes32 sha256Hash;
        string pHash;
        uint256 timestamp;
    }

    mapping(uint256 => CameraRecord) public cameraRecords;
    mapping(bytes32 => bool) public mintedHashes;

    event PhotoMinted(uint256 indexed tokenId, address indexed owner, string uuid, bytes32 sha256Hash);

    constructor(address defaultAdmin, address initialRelayer) ERC721("LensMint Camera", "LENS") {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(RELAYER_ROLE, initialRelayer);
    }

    function mintFromHardware(
        address to,
        string calldata uuid,
        bytes32 sha256Hash,
        string calldata pHash
    ) external onlyRole(RELAYER_ROLE) returns (uint256) {
        require(!mintedHashes[sha256Hash], "LensMint: Hash already minted");
        require(to != address(0), "LensMint: Zero address");

        uint256 tokenId = _nextTokenId++;
        
        mintedHashes[sha256Hash] = true;
        cameraRecords[tokenId] = CameraRecord({
            uuid: uuid,
            sha256Hash: sha256Hash,
            pHash: pHash,
            timestamp: block.timestamp
        });

        _safeMint(to, tokenId);

        emit PhotoMinted(tokenId, to, uuid, sha256Hash);
        
        return tokenId;
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}