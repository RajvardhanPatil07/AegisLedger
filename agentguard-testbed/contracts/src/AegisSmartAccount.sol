// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.36;

/// @title AegisSmartAccount
/// @notice Testnet-only smart account that re-enforces transaction policy on-chain.
/// @dev Checks-effects-interactions is used so nonces and budgets are committed before calls.
/// Source: https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern
contract AegisSmartAccount {
    enum Operation {
        NativeTransfer,
        ERC20Transfer,
        ContractCall
    }

    struct Execution {
        Operation operation;
        address target;
        uint256 value;
        bytes data;
        address asset;
        uint256 amount;
        address recipient;
        uint256 nonce;
        uint256 deadline;
    }

    struct SessionKey {
        uint128 budget;
        uint128 spent;
        uint64 validUntil;
        bool active;
    }

    bytes4 public constant ERC20_TRANSFER_SELECTOR = 0xa9059cbb;
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(uint8 operation,address target,uint256 value,bytes32 dataHash,address asset,uint256 amount,address recipient,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;
    address public immutable owner;
    uint256 public immutable perTransactionCap;
    uint256 public immutable lifetimeCap;

    uint256 public nonce;
    uint256 public totalSpent;
    bool public emergencyStopped;
    bool private executing;

    mapping(address => bool) public allowedAssets;
    mapping(address => bool) public allowedRecipients;
    mapping(address => bool) public allowedTargets;
    mapping(address => mapping(bytes4 => bool)) public allowedSelectors;
    mapping(address => SessionKey) public sessionKeys;

    error NotOwner();
    error EmergencyStopped();
    error InvalidNonce(uint256 expected, uint256 received);
    error AuthorizationExpired();
    error PerTransactionCapExceeded();
    error LifetimeCapExceeded();
    error AssetNotAllowed();
    error RecipientNotAllowed();
    error TargetNotAllowed();
    error SelectorNotAllowed();
    error InvalidCalldataBinding();
    error InvalidValueBinding();
    error InvalidSigner();
    error InvalidSignature();
    error SessionExpiredOrRevoked();
    error SessionBudgetExceeded();
    error ReentrantExecution();
    error ExecutionFailed(bytes returnData);

    event RuleUpdated(bytes32 indexed rule, address indexed subject, bytes4 selector, bool allowed);
    event SessionKeyUpdated(address indexed key, uint128 budget, uint64 validUntil, bool active);
    event EmergencyStopUpdated(bool stopped);
    event Executed(
        bytes32 indexed digest, address indexed signer, uint256 indexed nonce, uint256 amount
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (executing) revert ReentrantExecution();
        executing = true;
        _;
        executing = false;
    }

    constructor(address owner_, uint256 perTransactionCap_, uint256 lifetimeCap_) {
        require(owner_ != address(0), "owner is zero");
        require(perTransactionCap_ > 0, "per-transaction cap is zero");
        require(lifetimeCap_ >= perTransactionCap_, "lifetime cap below transaction cap");
        owner = owner_;
        perTransactionCap = perTransactionCap_;
        lifetimeCap = lifetimeCap_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("AegisSmartAccount"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    receive() external payable { }

    function setAsset(address asset, bool allowed) external onlyOwner {
        allowedAssets[asset] = allowed;
        emit RuleUpdated("ASSET", asset, bytes4(0), allowed);
    }

    function setRecipient(address recipient, bool allowed) external onlyOwner {
        allowedRecipients[recipient] = allowed;
        emit RuleUpdated("RECIPIENT", recipient, bytes4(0), allowed);
    }

    function setTarget(address target, bool allowed) external onlyOwner {
        allowedTargets[target] = allowed;
        emit RuleUpdated("TARGET", target, bytes4(0), allowed);
    }

    function setSelector(address target, bytes4 selector, bool allowed) external onlyOwner {
        allowedSelectors[target][selector] = allowed;
        emit RuleUpdated("SELECTOR", target, selector, allowed);
    }

    function setEmergencyStop(bool stopped) external onlyOwner {
        emergencyStopped = stopped;
        emit EmergencyStopUpdated(stopped);
    }

    function grantSessionKey(address key, uint128 budget, uint64 validUntil) external onlyOwner {
        require(key != address(0), "session key is zero");
        require(validUntil > block.timestamp, "session already expired");
        sessionKeys[key] =
            SessionKey({ budget: budget, spent: 0, validUntil: validUntil, active: true });
        emit SessionKeyUpdated(key, budget, validUntil, true);
    }

    function revokeSessionKey(address key) external onlyOwner {
        sessionKeys[key].active = false;
        emit SessionKeyUpdated(key, sessionKeys[key].budget, sessionKeys[key].validUntil, false);
    }

    function executionDigest(Execution calldata execution) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTION_TYPEHASH,
                uint8(execution.operation),
                execution.target,
                execution.value,
                keccak256(execution.data),
                execution.asset,
                execution.amount,
                execution.recipient,
                execution.nonce,
                execution.deadline
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    function execute(Execution calldata execution, bytes calldata signature)
        external
        payable
        nonReentrant
        returns (bytes memory returnData)
    {
        if (emergencyStopped) revert EmergencyStopped();
        if (execution.deadline < block.timestamp) revert AuthorizationExpired();
        if (execution.nonce != nonce) revert InvalidNonce(nonce, execution.nonce);
        if (execution.amount > perTransactionCap) revert PerTransactionCapExceeded();
        if (totalSpent + execution.amount > lifetimeCap) revert LifetimeCapExceeded();
        if (!allowedRecipients[execution.recipient]) revert RecipientNotAllowed();
        _validateOperation(execution);

        bytes32 digest = executionDigest(execution);
        address signer = _recover(digest, signature);
        if (signer != owner) {
            SessionKey storage session = sessionKeys[signer];
            if (!session.active || session.validUntil < block.timestamp) {
                revert SessionExpiredOrRevoked();
            }
            if (uint256(session.spent) + execution.amount > session.budget) {
                revert SessionBudgetExceeded();
            }
            session.spent += uint128(execution.amount);
        }

        nonce = execution.nonce + 1;
        totalSpent += execution.amount;
        // The allowlisted target, selector, recipient, value, and signer are all bound above.
        // slither-disable-next-line arbitrary-send-eth,low-level-calls
        (bool success, bytes memory result) =
            execution.target.call{ value: execution.value }(execution.data);
        if (!success) revert ExecutionFailed(result);
        emit Executed(digest, signer, execution.nonce, execution.amount);
        return result;
    }

    function _validateOperation(Execution calldata execution) internal view {
        if (execution.operation == Operation.NativeTransfer) {
            if (
                execution.asset != address(0) || execution.target != execution.recipient
                    || execution.value != execution.amount || execution.data.length != 0
                    || msg.value != execution.value
            ) revert InvalidValueBinding();
            return;
        }
        if (!allowedTargets[execution.target]) revert TargetNotAllowed();
        if (execution.data.length < 4) revert InvalidCalldataBinding();
        bytes4 selector = bytes4(execution.data[:4]);
        if (!allowedSelectors[execution.target][selector]) revert SelectorNotAllowed();

        if (execution.operation == Operation.ERC20Transfer) {
            if (msg.value != 0 || execution.value != 0) revert InvalidValueBinding();
            if (!allowedAssets[execution.asset]) revert AssetNotAllowed();
            if (execution.target != execution.asset || selector != ERC20_TRANSFER_SELECTOR) {
                revert InvalidCalldataBinding();
            }
            (address recipient, uint256 amount) = abi.decode(execution.data[4:], (address, uint256));
            if (recipient != execution.recipient || amount != execution.amount) {
                revert InvalidCalldataBinding();
            }
        } else {
            // A generic contract call can spend only native value; ERC-20 amount
            // parsing requires a separately allowlisted, selector-specific adapter.
            if (
                execution.asset != address(0) || execution.value != execution.amount
                    || msg.value != execution.value
            ) {
                revert InvalidValueBinding();
            }
        }
    }

    function _recover(bytes32 digest, bytes calldata signature) internal view returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (
            (v != 27 && v != 28)
                || uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
        ) revert InvalidSignature();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        if (signer != owner && !sessionKeys[signer].active) revert InvalidSigner();
        return signer;
    }
}
