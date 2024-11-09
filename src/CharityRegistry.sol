// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { console2 } from "forge-std/Test.sol";

contract CharityRegistry {
    address public admin;
    // @audit-info - need to emit events when changing these.
    mapping(address => bool) public verifiedCharities; // storage vars?
    mapping(address => bool) public registeredCharities; // storage vars? should emit event with updates

    constructor() {
        admin = msg.sender;
    }

    function registerCharity(address charity) public {
        registeredCharities[charity] = true;
    }

    function verifyCharity(address charity) public {
        require(msg.sender == admin, "Only admin can verify");
        require(registeredCharities[charity], "Charity not registered");
        verifiedCharities[charity] = true;
    }

    function isVerified(address charity) public view returns (bool) {
        // @audit-medium  - This should return the verified status of the charity, 
        // console2.log("isVerified: ", verifiedCharities[charity]);
        // console2.log("registeredCharities: ", registeredCharities[charity]);
        // console2.log("verifiedCharities: ", verifiedCharities[charity]);
        return registeredCharities[charity];
    }

    function changeAdmin(address newAdmin) public {
        // Zero address check should be used when changing admin
        require(msg.sender == admin, "Only admin can change admin");
        admin = newAdmin;
    }
}
