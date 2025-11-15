// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot++
 * @notice Advanced Merkle root registry with history, pausing, roles, and EIP-712 support.
 */

contract MetaRoot {
    // ------------------------------------------------------------------------
    // ERRORS
    // ------------------------------------------------------------------------
    error NotOwner();
    error NotAdminOrOwner();
    error ZeroAddress();
    error SameRoot();
    error ArrayLengthMismatch();
    error ETHNotAccepted();
    error InvalidName();
    error Paused();
    error InvalidSignature();

    // ------------------------------------------------------------------------
    // STATE
    // ------------------------------------------------------------------------
    address private _owner;
    uint256 private immutable _createdAt;

    // Admin mapping
    mapping(address => bool) private _admins;

    // Pausable flag
    bool private _paused;

    string private _contractName;

    bytes32 private _globalRoot;
    uint256 private _version;

    // chainId => root
    mapping(uint256 => bytes32) private _chainRoots;
    // chainId => time
    mapping(uint256 => uint256) private _chainUpdateTime;

    // ------------------------------------------------------------------------
    // ROOT HISTORY
    // ------------------------------------------------------------------------
    uint256 public constant GLOBAL_HISTORY_LIMIT = 20;
    struct GlobalHistory { bytes32 root; uint256 timestamp; }
    GlobalHistory[] private _globalHistory;

    struct ChainHistoryItem {
        bytes32 root;
        uint256 timestamp;
    }
    mapping(uint256 => ChainHistoryItem[]) private _chainHistory;

    // ------------------------------------------------------------------------
    // EIP-712
    // ------------------------------------------------------------------------
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 private constant ROOT_UPDATE_TYPEHASH =
        keccak256("RootUpdate(uint256 chainId,bytes32 newRoot,uint256 nonce)");

    mapping(address => uint256) public nonces;

    // ------------------------------------------------------------------------
    // EVENTS
    // ------------------------------------------------------------------------
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event AdminAdded(address admin);
    event AdminRemoved(address admin);
    event Paused();
    event Unpaused();
    event ContractRenamed(string oldName, string newName);

    event GlobalRootUpdated(
        address indexed updater,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 version,
        uint256 timestamp
    );

    event ChainRootUpdated(
        address indexed updater,
        uint256 indexed chainId,
        bytes32 indexed oldRoot,
        bytes32 newRoot,
        uint256 timestamp
    );

    // ------------------------------------------------------------------------
    // MODIFIERS
    // ------------------------------------------------------------------------
    modifier onlyOwner() {
        if (msg.sender != _owner) revert NotOwner();
        _;
    }

    modifier onlyAdminOrOwner() {
        if (msg.sender != _owner && !_admins[msg.sender]) revert NotAdminOrOwner();
        _;
    }

    modifier whenNotPaused() {
        if (_paused) revert Paused();
        _;
    }

    // ------------------------------------------------------------------------
    // CONSTRUCTOR
    // ------------------------------------------------------------------------
    constructor(string memory name_) {
        _owner = msg.sender;
        _createdAt = block.timestamp;
        _version = 1;

        _contractName = bytes(name_).length > 0 ? name_ : "MetaRoot++";

        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ------------------------------------------------------------------------
    // ROLE MANAGEMENT
    // ------------------------------------------------------------------------
    function addAdmin(address admin) external onlyOwner {
        if (admin == address(0)) revert ZeroAddress();
        _admins[admin] = true;
        emit AdminAdded(admin);
    }

    function removeAdmin(address admin) external onlyOwner {
        _admins[admin] = false;
        emit AdminRemoved(admin);
    }

    function isAdmin(address addr) external view returns (bool) {
        return _admins[addr];
    }

    // ------------------------------------------------------------------------
    // PAUSABLE
    // ------------------------------------------------------------------------
    function pause() external onlyOwner {
        _paused = true;
        emit Paused();
    }

    function unpause() external onlyOwner {
        _paused = false;
        emit Unpaused();
    }

    function isPaused() external view returns (bool) {
        return _paused;
    }

    // ------------------------------------------------------------------------
    // GLOBAL ROOT
    // ------------------------------------------------------------------------
    function setGlobalRoot(bytes32 newRoot)
        external
        onlyAdminOrOwner
        whenNotPaused
    {
        bytes32 old = _globalRoot;
        if (newRoot == old) revert SameRoot();

        _globalRoot = newRoot;
        unchecked { _version++; }

        _pushGlobalHistory(newRoot);

        emit GlobalRootUpdated(msg.sender, old, newRoot, _version, block.timestamp);
    }

    function _pushGlobalHistory(bytes32 root) private {
        _globalHistory.push(GlobalHistory(root, block.timestamp));
        if (_globalHistory.length > GLOBAL_HISTORY_LIMIT) {
            _globalHistory.pop();
        }
    }

    function getGlobalHistory() external view returns (GlobalHistory[] memory) {
        return _globalHistory;
    }

    // ------------------------------------------------------------------------
    // CHAIN ROOT
    // ------------------------------------------------------------------------
    function setChainRoot(uint256 chainId, bytes32 newRoot)
        external
        onlyAdminOrOwner
        whenNotPaused
    {
        bytes32 old = _chainRoots[chainId];
        if (newRoot == old) revert SameRoot();

        _chainRoots[chainId] = newRoot;
        _chainUpdateTime[chainId] = block.timestamp;

        _chainHistory[chainId].push(ChainHistoryItem(newRoot, block.timestamp));

        emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
    }

    function getChainHistory(uint256 chainId)
        external
        view
        returns (ChainHistoryItem[] memory)
    {
        return _chainHistory[chainId];
    }

    // ------------------------------------------------------------------------
    // EIP-712 SIGN-BASED UPDATES (meta-transactions)
    // ------------------------------------------------------------------------
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(_contractName)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function updateChainRootBySig(
        uint256 chainId,
        bytes32 newRoot,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(abi.encode(ROOT_UPDATE_TYPEHASH, chainId, newRoot, nonce))
            )
        );

        address signer = _recover(digest, signature);
        if (signer != _owner) revert InvalidSignature();
        if (nonce != nonces[signer]++) revert InvalidSignature();

        setChainRoot(chainId, newRoot); // uses existing logic
    }

    function _recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        return ecrecover(hash, v, r, s);
    }

    // ------------------------------------------------------------------------
    // METADATA
    // ------------------------------------------------------------------------
    function renameContract(string calldata newName) external onlyOwner {
        if (bytes(newName).length == 0) revert InvalidName();
        string memory old = _contractName;
        _contractName = newName;
        emit ContractRenamed(old, newName);
    }

    // ------------------------------------------------------------------------
    // FALLBACK
    // ------------------------------------------------------------------------
    receive() external payable { revert ETHNotAccepted(); }
    fallback() external payable { revert(); }
}
