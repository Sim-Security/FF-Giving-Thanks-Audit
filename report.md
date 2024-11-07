# Aderyn Analysis Report

This report was generated by [Aderyn](https://github.com/Cyfrin/aderyn), a static analysis tool built by [Cyfrin](https://cyfrin.io), a blockchain security company. This report is not a substitute for manual audit or security review. It should not be relied upon for any purpose other than to assist in the identification of potential security vulnerabilities.
# Table of Contents

- [Summary](#summary)
  - [Files Summary](#files-summary)
  - [Files Details](#files-details)
  - [Issue Summary](#issue-summary)
- [High Issues](#high-issues)
  - [H-1: `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`](#h-1-abiencodepacked-should-not-be-used-with-dynamic-types-when-passing-the-result-to-a-hash-function-such-as-keccak256)
  - [H-2: Functions send eth away from contract but performs no checks on any address.](#h-2-functions-send-eth-away-from-contract-but-performs-no-checks-on-any-address)
- [Low Issues](#low-issues)
  - [L-1: Solidity pragma should be specific, not wide](#l-1-solidity-pragma-should-be-specific-not-wide)
  - [L-2: Missing checks for `address(0)` when assigning values to address state variables](#l-2-missing-checks-for-address0-when-assigning-values-to-address-state-variables)
  - [L-3: `public` functions not used internally could be marked `external`](#l-3-public-functions-not-used-internally-could-be-marked-external)
  - [L-4: Using `ERC721::_mint()` can be dangerous](#l-4-using-erc721mint-can-be-dangerous)
  - [L-5: PUSH0 is not supported by all chains](#l-5-push0-is-not-supported-by-all-chains)
  - [L-6: State variable changes but no event is emitted.](#l-6-state-variable-changes-but-no-event-is-emitted)
  - [L-7: State variable could be declared immutable](#l-7-state-variable-could-be-declared-immutable)


# Summary

## Files Summary

| Key | Value |
| --- | --- |
| .sol Files | 2 |
| Total nSLOC | 67 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| src/CharityRegistry.sol | 24 |
| src/GivingThanks.sol | 43 |
| **Total** | **67** |


## Issue Summary

| Category | No. of Issues |
| --- | --- |
| High | 2 |
| Low | 7 |


# High Issues

## H-1: `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`

Use `abi.encode()` instead which will pad items to 32 bytes, which will [prevent hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode) (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but `abi.encode(0x123,0x456)` => `0x0...1230...456`). Unless there is a compelling reason, `abi.encode` should be preferred. If there is only one argument to `abi.encodePacked()` it can often be cast to `bytes()` or `bytes32()` [instead](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).
If all arguments are strings and or bytes, `bytes.concat()` should be used instead.

<details><summary>2 Found Instances</summary>


- Found in src/GivingThanks.sol [Line: 40](src/GivingThanks.sol#L40)

	```solidity
	            abi.encodePacked(
	```

- Found in src/GivingThanks.sol [Line: 55](src/GivingThanks.sol#L55)

	```solidity
	        return string(abi.encodePacked("data:application/json;base64,", base64Json));
	```

</details>



## H-2: Functions send eth away from contract but performs no checks on any address.

Consider introducing checks for `msg.sender` to ensure the recipient of the money is as intended.

<details><summary>1 Found Instances</summary>


- Found in src/GivingThanks.sol [Line: 21](src/GivingThanks.sol#L21)

	```solidity
	    function donate(address charity) public payable {
	```

</details>



# Low Issues

## L-1: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>2 Found Instances</summary>


- Found in src/CharityRegistry.sol [Line: 2](src/CharityRegistry.sol#L2)

	```solidity
	pragma solidity ^0.8.0;
	```

- Found in src/GivingThanks.sol [Line: 2](src/GivingThanks.sol#L2)

	```solidity
	pragma solidity ^0.8.0;
	```

</details>



## L-2: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/CharityRegistry.sol [Line: 29](src/CharityRegistry.sol#L29)

	```solidity
	        admin = newAdmin;
	```

- Found in src/GivingThanks.sol [Line: 60](src/GivingThanks.sol#L60)

	```solidity
	        registry = CharityRegistry(_registry);
	```

</details>



## L-3: `public` functions not used internally could be marked `external`

Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.

<details><summary>6 Found Instances</summary>


- Found in src/CharityRegistry.sol [Line: 13](src/CharityRegistry.sol#L13)

	```solidity
	    function registerCharity(address charity) public {
	```

- Found in src/CharityRegistry.sol [Line: 17](src/CharityRegistry.sol#L17)

	```solidity
	    function verifyCharity(address charity) public {
	```

- Found in src/CharityRegistry.sol [Line: 23](src/CharityRegistry.sol#L23)

	```solidity
	    function isVerified(address charity) public view returns (bool) {
	```

- Found in src/CharityRegistry.sol [Line: 27](src/CharityRegistry.sol#L27)

	```solidity
	    function changeAdmin(address newAdmin) public {
	```

- Found in src/GivingThanks.sol [Line: 21](src/GivingThanks.sol#L21)

	```solidity
	    function donate(address charity) public payable {
	```

- Found in src/GivingThanks.sol [Line: 59](src/GivingThanks.sol#L59)

	```solidity
	    function updateRegistry(address _registry) public {
	```

</details>



## L-4: Using `ERC721::_mint()` can be dangerous

Using `ERC721::_mint()` can mint ERC721 tokens to addresses which don't support ERC721 tokens. Use `_safeMint()` instead of `_mint()` for ERC721.

<details><summary>1 Found Instances</summary>


- Found in src/GivingThanks.sol [Line: 27](src/GivingThanks.sol#L27)

	```solidity
	        _mint(msg.sender, tokenCounter);
	```

</details>



## L-5: PUSH0 is not supported by all chains

Solc compiler version 0.8.20 switches the default target EVM version to Shanghai, which means that the generated bytecode will include PUSH0 opcodes. Be sure to select the appropriate EVM version in case you intend to deploy on a chain other than mainnet like L2 chains that may not support PUSH0, otherwise deployment of your contracts will fail.

<details><summary>2 Found Instances</summary>


- Found in src/CharityRegistry.sol [Line: 2](src/CharityRegistry.sol#L2)

	```solidity
	pragma solidity ^0.8.0;
	```

- Found in src/GivingThanks.sol [Line: 2](src/GivingThanks.sol#L2)

	```solidity
	pragma solidity ^0.8.0;
	```

</details>



## L-6: State variable changes but no event is emitted.

State variable changes in this function but no event is emitted.

<details><summary>5 Found Instances</summary>


- Found in src/CharityRegistry.sol [Line: 13](src/CharityRegistry.sol#L13)

	```solidity
	    function registerCharity(address charity) public {
	```

- Found in src/CharityRegistry.sol [Line: 17](src/CharityRegistry.sol#L17)

	```solidity
	    function verifyCharity(address charity) public {
	```

- Found in src/CharityRegistry.sol [Line: 27](src/CharityRegistry.sol#L27)

	```solidity
	    function changeAdmin(address newAdmin) public {
	```

- Found in src/GivingThanks.sol [Line: 21](src/GivingThanks.sol#L21)

	```solidity
	    function donate(address charity) public payable {
	```

- Found in src/GivingThanks.sol [Line: 59](src/GivingThanks.sol#L59)

	```solidity
	    function updateRegistry(address _registry) public {
	```

</details>



## L-7: State variable could be declared immutable

State variables that are should be declared immutable to save gas. Add the `immutable` attribute to state variables that are only changed in the constructor

<details><summary>1 Found Instances</summary>


- Found in src/GivingThanks.sol [Line: 13](src/GivingThanks.sol#L13)

	```solidity
	    address public owner;
	```

</details>


