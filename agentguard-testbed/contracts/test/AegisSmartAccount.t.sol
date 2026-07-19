// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

import { AegisSmartAccount } from "../src/AegisSmartAccount.sol";
import { TestBase } from "./TestBase.sol";

contract MockToken {
    mapping(address => uint256) public balanceOf;

    function mint(address recipient, uint256 amount) external {
        balanceOf[recipient] += amount;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract ReentrantTarget {
    AegisSmartAccount public immutable account;
    bytes public nestedCall;
    bytes4 public failureSelector;

    constructor(AegisSmartAccount account_) {
        account = account_;
    }

    function configure(bytes calldata payload) external {
        nestedCall = payload;
    }

    function attack() external {
        (bool success, bytes memory result) = address(account).call(nestedCall);
        require(!success, "nested execution unexpectedly succeeded");
        if (result.length >= 4) {
            bytes4 selector;
            assembly ("memory-safe") {
                selector := mload(add(result, 32))
            }
            failureSelector = selector;
        }
    }
}

contract AegisSmartAccountTest is TestBase {
    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant SESSION_KEY = 0xB0B;
    uint256 internal constant ATTACKER_KEY = 0xBAD;
    uint256 internal constant PER_TRANSACTION_CAP = 100 ether;
    uint256 internal constant LIFETIME_CAP = 500 ether;

    AegisSmartAccount internal account;
    MockToken internal token;
    address internal owner;
    address internal recipient = address(0xBEEF);

    function setUp() public {
        owner = vm.addr(OWNER_KEY);
        account = new AegisSmartAccount(owner, PER_TRANSACTION_CAP, LIFETIME_CAP);
        token = new MockToken();
        token.mint(address(account), 1_000 ether);
        vm.prank(owner);
        account.setAsset(address(token), true);
        vm.prank(owner);
        account.setTarget(address(token), true);
        vm.prank(owner);
        account.setRecipient(recipient, true);
        vm.prank(owner);
        account.setSelector(address(token), MockToken.transfer.selector, true);
    }

    function testOwnerAuthorizedTransferSettlesAndConsumesNonce() public {
        AegisSmartAccount.Execution memory execution = _transfer(25 ether, 0, recipient);
        account.execute(execution, _sign(execution, OWNER_KEY));
        assertEq(token.balanceOf(recipient), 25 ether);
        assertEq(account.nonce(), 1);
        assertEq(account.totalSpent(), 25 ether);
    }

    function testDirectRpcSubmissionWithoutAuthorizedSignerCannotBypassRules() public {
        AegisSmartAccount.Execution memory execution = _transfer(25 ether, 0, recipient);
        bytes memory signature = _sign(execution, ATTACKER_KEY);
        vm.expectRevert(AegisSmartAccount.InvalidSigner.selector);
        account.execute(execution, signature);
    }

    function testReplayIsRejected() public {
        AegisSmartAccount.Execution memory execution = _transfer(10 ether, 0, recipient);
        bytes memory signature = _sign(execution, OWNER_KEY);
        account.execute(execution, signature);
        vm.expectPartialRevert(AegisSmartAccount.InvalidNonce.selector);
        account.execute(execution, signature);
    }

    function testAllowlistedTargetCannotReenterExecution() public {
        ReentrantTarget target = new ReentrantTarget(account);
        vm.prank(owner);
        account.setTarget(address(target), true);
        vm.prank(owner);
        account.setSelector(address(target), ReentrantTarget.attack.selector, true);

        AegisSmartAccount.Execution memory nested = _transfer(10 ether, 1, recipient);
        target.configure(
            abi.encodeCall(AegisSmartAccount.execute, (nested, _sign(nested, OWNER_KEY)))
        );
        AegisSmartAccount.Execution memory outer = AegisSmartAccount.Execution({
            operation: AegisSmartAccount.Operation.ContractCall,
            target: address(target),
            value: 0,
            data: abi.encodeCall(ReentrantTarget.attack, ()),
            asset: address(0),
            amount: 0,
            recipient: recipient,
            nonce: 0,
            deadline: block.timestamp + 5 minutes
        });

        account.execute(outer, _sign(outer, OWNER_KEY));

        assertEq(
            uint256(uint32(target.failureSelector())),
            uint256(uint32(AegisSmartAccount.ReentrantExecution.selector))
        );
        assertEq(account.nonce(), 1);
        assertEq(token.balanceOf(recipient), 0);
    }

    function testPerTransactionAndRecipientRulesCannotBeBypassed() public {
        AegisSmartAccount.Execution memory excessive = _transfer(101 ether, 0, recipient);
        bytes memory excessiveSignature = _sign(excessive, OWNER_KEY);
        vm.expectRevert(AegisSmartAccount.PerTransactionCapExceeded.selector);
        account.execute(excessive, excessiveSignature);

        AegisSmartAccount.Execution memory unknown = _transfer(10 ether, 0, address(0xCAFE));
        bytes memory unknownSignature = _sign(unknown, OWNER_KEY);
        vm.expectRevert(AegisSmartAccount.RecipientNotAllowed.selector);
        account.execute(unknown, unknownSignature);
    }

    function testCalldataRecipientAndAmountAreBound() public {
        AegisSmartAccount.Execution memory execution = _transfer(10 ether, 0, recipient);
        execution.data = abi.encodeCall(MockToken.transfer, (recipient, 11 ether));
        bytes memory signature = _sign(execution, OWNER_KEY);
        vm.expectRevert(AegisSmartAccount.InvalidCalldataBinding.selector);
        account.execute(execution, signature);
    }

    function testSelectorRestrictionAndEmergencyStop() public {
        vm.prank(owner);
        account.setSelector(address(token), MockToken.transfer.selector, false);
        AegisSmartAccount.Execution memory execution = _transfer(10 ether, 0, recipient);
        bytes memory signature = _sign(execution, OWNER_KEY);
        vm.expectRevert(AegisSmartAccount.SelectorNotAllowed.selector);
        account.execute(execution, signature);

        vm.prank(owner);
        account.setSelector(address(token), MockToken.transfer.selector, true);
        vm.prank(owner);
        account.setEmergencyStop(true);
        vm.expectRevert(AegisSmartAccount.EmergencyStopped.selector);
        account.execute(execution, signature);
    }

    function testSessionKeyBudgetAndRevocation() public {
        address session = vm.addr(SESSION_KEY);
        vm.prank(owner);
        account.grantSessionKey(session, 20 ether, uint64(block.timestamp + 1 days));
        AegisSmartAccount.Execution memory first = _transfer(15 ether, 0, recipient);
        account.execute(first, _sign(first, SESSION_KEY));

        AegisSmartAccount.Execution memory overBudget = _transfer(6 ether, 1, recipient);
        bytes memory overBudgetSignature = _sign(overBudget, SESSION_KEY);
        vm.expectRevert(AegisSmartAccount.SessionBudgetExceeded.selector);
        account.execute(overBudget, overBudgetSignature);

        vm.prank(owner);
        account.revokeSessionKey(session);
        AegisSmartAccount.Execution memory revoked = _transfer(1 ether, 1, recipient);
        bytes memory revokedSignature = _sign(revoked, SESSION_KEY);
        vm.expectRevert(AegisSmartAccount.InvalidSigner.selector);
        account.execute(revoked, revokedSignature);
    }

    function _transfer(uint256 amount, uint256 executionNonce, address paymentRecipient)
        internal
        view
        returns (AegisSmartAccount.Execution memory)
    {
        return AegisSmartAccount.Execution({
            operation: AegisSmartAccount.Operation.ERC20Transfer,
            target: address(token),
            value: 0,
            data: abi.encodeCall(MockToken.transfer, (paymentRecipient, amount)),
            asset: address(token),
            amount: amount,
            recipient: paymentRecipient,
            nonce: executionNonce,
            deadline: block.timestamp + 5 minutes
        });
    }

    function _sign(AegisSmartAccount.Execution memory execution, uint256 key)
        internal
        returns (bytes memory)
    {
        bytes32 digest = account.executionDigest(execution);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
