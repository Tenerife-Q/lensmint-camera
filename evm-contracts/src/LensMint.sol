// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract LensMint is ERC721, Ownable {
    uint256 private _nextTokenId;

    // Track authorized cameras
    mapping(string => bool) public registeredDevices;
    // Prevent image hash replay
    mapping(bytes32 => bool) public mintedHashes;

    event DeviceRegistered(string indexed deviceId);
    event HardwareMinted(uint256 indexed tokenId, string uuid, bytes32 indexed sha256Hash);

    constructor() ERC721("LensMint Physical NFT", "LMP") Ownable(msg.sender) {}

    // Add device to whitelist
    function registerDevice(string calldata deviceId) external onlyOwner {
        registeredDevices[deviceId] = true;
        emit DeviceRegistered(deviceId);
    }

    // Direct hardware minting verify execution
    function mintFromHardware(
        address to,
        string calldata uuid,
        bytes32 sha256Hash,
        string calldata phash,
        string calldata deviceId
    ) external returns (uint256) {
        // Assertions
        require(registeredDevices[deviceId], "Unauthorized device");
        require(!mintedHashes[sha256Hash], "Duplicate asset hash");

        uint256 tokenId = _nextTokenId++;
        mintedHashes[sha256Hash] = true;

        _safeMint(to, tokenId);

        // Metadata parameters binding placeholder
        string memory _uuid = uuid;
        string memory _phash = phash;
        bytes32 _hash = sha256Hash;
        
        emit HardwareMinted(tokenId, _uuid, _hash);

        return tokenId;
    }
}