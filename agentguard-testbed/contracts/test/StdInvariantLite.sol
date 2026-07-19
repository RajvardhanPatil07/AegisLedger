// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.36;

/// @notice Minimal invariant target registry matching Forge's discovery interface.
/// @dev Interface shapes follow foundry-rs/forge-std StdInvariant for Foundry 1.7.1.
/// Source: https://github.com/foundry-rs/forge-std/blob/master/src/StdInvariant.sol
abstract contract StdInvariantLite {
    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    struct FuzzArtifactSelector {
        string artifact;
        bytes4[] selectors;
    }

    struct FuzzInterface {
        address addr;
        string[] artifacts;
    }

    address[] private targetedContracts;

    function targetContract(address target) internal {
        targetedContracts.push(target);
    }

    function excludeArtifacts() public pure returns (string[] memory values) {
        values = new string[](0);
    }

    function excludeContracts() public pure returns (address[] memory values) {
        values = new address[](0);
    }

    function excludeSelectors() public pure returns (FuzzSelector[] memory values) {
        values = new FuzzSelector[](0);
    }

    function excludeSenders() public pure returns (address[] memory values) {
        values = new address[](0);
    }

    function targetArtifacts() public pure returns (string[] memory values) {
        values = new string[](0);
    }

    function targetArtifactSelectors() public pure returns (FuzzArtifactSelector[] memory values) {
        values = new FuzzArtifactSelector[](0);
    }

    function targetContracts() public view returns (address[] memory values) {
        values = targetedContracts;
    }

    function targetSelectors() public pure returns (FuzzSelector[] memory values) {
        values = new FuzzSelector[](0);
    }

    function targetSenders() public pure returns (address[] memory values) {
        values = new address[](0);
    }

    function targetInterfaces() public pure returns (FuzzInterface[] memory values) {
        values = new FuzzInterface[](0);
    }
}
