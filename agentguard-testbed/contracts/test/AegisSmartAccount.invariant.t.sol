// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

import { AegisSmartAccount } from "../src/AegisSmartAccount.sol";
import { MockToken } from "./AegisSmartAccount.t.sol";
import { StdInvariantLite } from "./StdInvariantLite.sol";
import { TestBase } from "./TestBase.sol";

contract AccountHandler is TestBase {
    uint256 internal constant OWNER_KEY = 0xA11CE;
    AegisSmartAccount public immutable account;
    MockToken public immutable token;
    address public immutable recipient;
    uint256 public successfulCalls;

    constructor(AegisSmartAccount account_, MockToken token_, address recipient_) {
        account = account_;
        token = token_;
        recipient = recipient_;
    }

    function pay(uint96 rawAmount) external {
        uint256 remaining = account.lifetimeCap() - account.totalSpent();
        if (remaining == 0) return;
        uint256 maximum =
            remaining < account.perTransactionCap() ? remaining : account.perTransactionCap();
        uint256 amount = (uint256(rawAmount) % maximum) + 1;
        AegisSmartAccount.Execution memory execution = AegisSmartAccount.Execution({
            operation: AegisSmartAccount.Operation.ERC20Transfer,
            target: address(token),
            value: 0,
            data: abi.encodeCall(MockToken.transfer, (recipient, amount)),
            asset: address(token),
            amount: amount,
            recipient: recipient,
            nonce: account.nonce(),
            deadline: block.timestamp + 5 minutes
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, account.executionDigest(execution));
        account.execute(execution, abi.encodePacked(r, s, v));
        successfulCalls += 1;
    }
}

contract AegisSmartAccountInvariantTest is TestBase, StdInvariantLite {
    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant PER_TRANSACTION_CAP = 100 ether;
    uint256 internal constant LIFETIME_CAP = 500 ether;

    AegisSmartAccount internal account;
    MockToken internal token;
    AccountHandler internal handler;
    address internal recipient = address(0xBEEF);

    function setUp() public {
        address owner = vm.addr(OWNER_KEY);
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
        handler = new AccountHandler(account, token, recipient);
        targetContract(address(handler));
    }

    function invariantNonceTracksOnlySuccessfulExecutions() public view {
        assertEq(account.nonce(), handler.successfulCalls());
    }

    function invariantLifetimeCapCannotBeExceeded() public view {
        assertLe(account.totalSpent(), LIFETIME_CAP);
        assertEq(token.balanceOf(recipient), account.totalSpent());
    }
}
