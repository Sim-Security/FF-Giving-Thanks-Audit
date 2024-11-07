// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CharityRegistry.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import { console2} from "forge-std/Test.sol";

contract GivingThanks is ERC721URIStorage {
    CharityRegistry public registry;
    uint256 public tokenCounter;
    address public owner;

    // I think we want the owner of this contract to be the registry contract, not the deployer of this contract.
    constructor(address _registry) ERC721("DonationReceipt", "DRC") {
        // @audit-medium - This should be CharistyRegistry(_registry) to ensure that the registry is the being pointed to and not the deployer of this contract.

        // @notice Going to fix for auditing purposes. Will change at end of audit
        // registry = CharityRegistry(msg.sender); // This points the registry to the msg.sender, not the registry contract.
        registry = CharityRegistry(_registry);
        
        owner = msg.sender;
        tokenCounter = 0;
    }

    function donate(address charity) public payable {
        console2.log(registry.isVerified(charity));
        require(registry.isVerified(charity), "Charity not verified");
        // @audit-medium - The donor can donate 0 ether to the charity, and receive an NFT. Not good for the charity.
        (bool sent,) = charity.call{value: msg.value}(""); // good for gas optimization
        require(sent, "Failed to send Ether");

        // @audit-high - reentrancy, the donor can mint unlimited NFTs by reentering the call
        // @audit-medium - This should be a safe mint to make sure contract can deal with ERC721
        _mint(msg.sender, tokenCounter);
        // @audit-low - should emit an event for the minting of the token

        // Create metadata for the tokenURI
        string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
        _setTokenURI(tokenCounter, uri);

        tokenCounter += 1;
    }

    function _createTokenURI(address donor, uint256 date, uint256 amount) internal pure returns (string memory) {
        // Create JSON metadata
        string memory json = string(
            abi.encodePacked(
                '{"donor":"',
                Strings.toHexString(uint160(donor), 20),
                '","date":"',
                Strings.toString(date),
                '","amount":"',
                Strings.toString(amount),
                '"}'
            )
        );

        // Encode in base64 using OpenZeppelin's Base64 library
        string memory base64Json = Base64.encode(bytes(json));

        // Return the data URL
        return string(abi.encodePacked("data:application/json;base64,", base64Json));
    }

    // q what actually haappens here? Can anyone change the registry? to there own address?
    // Anyone can change the registry address to their own address 
    // @audit-medium - This should only be callable by the owner of the contract, Otherwise a malicious contract can be created to bypass charity verification checks
    function updateRegistry(address _registry) public {
        registry = CharityRegistry(_registry);
    }
}
