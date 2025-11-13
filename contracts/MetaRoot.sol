// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot
 * @notice Decentralized storage for a global Merkle/metadata root and per-chain roots.
 * @dev Ownership, versioning, batch operations and event transparency.
 */
contract MetaRoot {
    // ------------------------------------------------------------------------
    // STATE
    // ------------------------------------------------------------------------

    address private _owner;                     // Contract owner
    bytes32 private _globalRoot;                // Global root (Merkle or metadata root)
    uint256 private _version;                   // Version counter for global updates
    uint256 private immutable _createdAt;       // Contract creation timestamp (immutable)
    string private _contractName;               // Optional label for UI/tracking

    // chainId => root
    mapping(uint256 => bytes32) private _chainRoots;
    // chainId => last update timestamp
    mapping(uint256 => uint256) private _chainUpdateTime;

    // ------------------------------------------------------------------------
    // EVENTS
    // ------------------------------------------------------------------------

    /// @notice Emitted when ownership changes
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when the global root is updated
    /// @dev index bytes32 roots for easier on-chain filtering
    event GlobalRootUpdated(
        address indexed updater,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 version,
        uint256 timestamp
    );

    /// @notice Emitted when a chain root is updated
    event ChainRootUpdated(
        address indexed updater,
        uint256 indexed chainId,
        bytes32 indexed oldRoot,
        bytes32 newRoot,
        uint256 timestamp
    );

    /// @notice Emitted when the contract name is changed
    event ContractRenamed(string oldName, string newName);

    // ------------------------------------------------------------------------
    // MODIFIERS
    // ------------------------------------------------------------------------

    modifier onlyOwner() {
        require(msg.sender == _owner, "MetaRoot: caller is not the owner");
        _;
    }

    // ------------------------------------------------------------------------
    // CONSTRUCTOR
    // ------------------------------------------------------------------------

    /**
     * @notice Initialize contract with optional name
     * @param name_ Optional contract name
     */
    constructor(string memory name_) {
        _owner = msg.sender;
        _version = 1;
        _createdAt = block.timestamp;
        _contractName = bytes(name_).length > 0 ? name_ : "MetaRoot";
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ------------------------------------------------------------------------
    // OWNERSHIP
    // ------------------------------------------------------------------------

    /// @notice Current owner address
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @notice Transfer contract ownership
     * @param newOwner Address to receive ownership (non-zero)
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "MetaRoot: new owner is zero address");
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    // ------------------------------------------------------------------------
    // GLOBAL ROOT API
    // ------------------------------------------------------------------------

    /// @notice Return global root
    function getGlobalRoot() external view returns (bytes32) {
        return _globalRoot;
    }

    /// @notice Return current global version
    function getGlobalVersion() external view returns (uint256) {
        return _version;
    }

    /// @notice Return contract age in seconds
    function getContractAge() external view returns (uint256) {
        return block.timestamp - _createdAt;
    }

    /**
     * @notice Set or update the global root
     * @dev Does nothing if the new root equals the old root (prevents unnecessary version bumps)
     * @param newRoot The new global root value
     */
    function setGlobalRoot(bytes32 newRoot) external onlyOwner {
        bytes32 old = _globalRoot;
        require(newRoot != old, "MetaRoot: new root equals current root");

        _globalRoot = newRoot;
        _version += 1;
        emit GlobalRootUpdated(msg.sender, old, newRoot, _version, block.timestamp);
    }

    // ------------------------------------------------------------------------
    // CHAIN ROOT API
    // ------------------------------------------------------------------------

    /// @notice Get root for a chainId
    function getChainRoot(uint256 chainId) external view returns (bytes32) {
        return _chainRoots[chainId];
    }

    /// @notice Get last update time for a chainId
    function getChainUpdateTime(uint256 chainId) external view returns (uint256) {
        return _chainUpdateTime[chainId];
    }

    /**
     * @notice Set or update a single chain root
     * @param chainId Target chain id
     * @param newRoot New root to assign
     */
    function setChainRoot(uint256 chainId, bytes32 newRoot) external onlyOwner {
        bytes32 old = _chainRoots[chainId];
        require(newRoot != old, "MetaRoot: new root equals current root");

        _chainRoots[chainId] = newRoot;
        _chainUpdateTime[chainId] = block.timestamp;
        emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
    }

    /**
     * @notice Batch set multiple chain roots
     * @param chainIds Array of chain ids
     * @param roots Array of corresponding roots
     */
    function batchSetChainRoots(uint256[] calldata chainIds, bytes32[] calldata roots) external onlyOwner {
        uint256 len = chainIds.length;
        require(len == roots.length, "MetaRoot: array length mismatch");
        for (uint256 i = 0; i < len; ) {
            uint256 chainId = chainIds[i];
            bytes32 old = _chainRoots[chainId];
            bytes32 newRoot = roots[i];
            if (newRoot != old) {
                _chainRoots[chainId] = newRoot;
                _chainUpdateTime[chainId] = block.timestamp;
                emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
            }
            unchecked { ++i; } // small gas save, safe because loop bound checked
        }
    }

    /**
     * @notice Batch getter for multiple chain roots (read-only)
     * @param chainIds Array of chain ids to query
     * @return roots Array of roots in same order as chainIds
     */
    function getChainRoots(uint256[] calldata chainIds) external view returns (bytes32[] memory roots) {
        uint256 len = chainIds.length;
        roots = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            roots[i] = _chainRoots[chainIds[i]];
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------------------
    // CONTRACT METADATA / UTILITY
    // ------------------------------------------------------------------------

    /// @notice Contract display name
    function getContractName() external view returns (string memory) {
        return _contractName;
    }

    /**
     * @notice Rename contract (for UI / tracking)
     * @param newName New display name
     */
    function renameContract(string calldata newName) external onlyOwner {
        string memory oldName = _contractName;
        _contractName = newName;
        emit ContractRenamed(oldName, newName);
    }

    /**
     * @notice Renounce ownership (irreversible)
     */
    function renounceOwnership() external onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @notice Get a compact summary of contract details
     * @return name Contract name
     * @return owner_ Owner address
     * @return version_ Current global version
     * @return createdAt_ Creation timestamp
     * @return globalRoot_ Current global root
     */
    function getContractDetails()
        external
        view
        returns (
            string memory name,
            address owner_,
            uint256 version_,
            uint256 createdAt_,
            bytes32 globalRoot_
        )
    {
        return (_contractName, _owner, _version, _createdAt, _globalRoot);
    }

    /// @notice Check whether an address is owner
    function isOwner(address addr) external view returns (bool) {
        return addr == _owner;
    }

    // ------------------------------------------------------------------------
    // FALLBACK / RECEIVE
    // ------------------------------------------------------------------------

    receive() external payable {
        revert("MetaRoot: direct ETH not accepted");
    }

    fallback() external payable {
        revert("MetaRoot: invalid call");
    }
}
