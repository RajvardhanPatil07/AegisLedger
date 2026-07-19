// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function expectRevert(bytes4 selector) external;
    function expectPartialRevert(bytes4 selector) external;
    function warp(uint256 timestamp) external;
}

abstract contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertEq(uint256 actual, uint256 expected) internal pure {
        require(actual == expected, "uint values differ");
    }

    function assertEq(address actual, address expected) internal pure {
        require(actual == expected, "address values differ");
    }

    function assertLe(uint256 actual, uint256 maximum) internal pure {
        require(actual <= maximum, "value exceeds maximum");
    }
}
