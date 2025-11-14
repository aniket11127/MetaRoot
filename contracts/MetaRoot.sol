// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot
 * @notice Decentralized storage for a global Merkle/metadata root and per-chain roots.
 * @dev Ownership, versioning, batch operations and event transparency.
 */
contract MetaRoot {
    // ------------------------------------------------------------------------
    // ERRORS (cheaper than string requires)
    // ------------------------------------------------------------------------
    error NotOwner();
    error ZeroAddress();
    error SameRoot();
    error ArrayLengthMismatch();
    error ETHNotAccepted();
    error InvalidName();

    // ------------------------------------------------------------------------
    // STATE
    // ------------------------------------------------------------------------
    address private _owner;                     // Contract owner (mutable)
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
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when the global root is updated
    event GlobalRootUpdated(
        address indexed updater,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 version,
        uint256 timestamp
    );

    /// @notice Emitted when a chain root is updated (per chain)
    event ChainRootUpdated(
        address indexed updater,
        uint256 indexed chainId,
        bytes32 indexed oldRoot,
        bytes32 newRoot,
        uint256 timestamp
    );

    /// @notice Emitted when the contract display name is changed
    event ContractRenamed(string oldName, string newName);

    /// @notice (Optional) Emitted when batch update completes (helps off-chain indexing)
    event BatchChainRootsUpdated(address indexed updater, uint256 indexed count, uint256 timestamp);

    // ------------------------------------------------------------------------
    // MODIFIERS
    // ------------------------------------------------------------------------
    modifier onlyOwner() {
        if (msg.sender != _owner) revert NotOwner();
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
        _version = 1; // starts at 1
        _createdAt = block.timestamp;
        _contractName = bytes(name_).length > 0 ? name_ : "MetaRoot";
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ------------------------------------------------------------------------
    // OWNERSHIP
    // ------------------------------------------------------------------------

    /// @notice Current owner address
    function owner() external view returns (address) {
        return _owner;
    }

    /**
     * @notice Transfer contract ownership
     * @param newOwner Address to receive ownership (non-zero)
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
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
        if (newRoot == old) revert SameRoot();

        _globalRoot = newRoot;
        // bump version after changing root
        unchecked { _version += 1; }
        emit GlobalRootUpdated(msg.sender, old, newRoot, _version, block.timestamp);
    }

    /**
     * @notice Force update the global root and version even if equal (useful in some rollups)
     * @param newRoot The new global root value
     * @dev Use sparingly; will increment version regardless
     */
    function forceSetGlobalRoot(bytes32 newRoot) external onlyOwner {
        bytes32 old = _globalRoot;
        _globalRoot = newRoot;
        unchecked { _version += 1; }
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
        if (newRoot == old) revert SameRoot();

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
        if (len != roots.length) revert ArrayLengthMismatch();
        // cache for slightly cheaper access
        for (uint256 i = 0; i < len; ) {
            uint256 chainId = chainIds[i];
            bytes32 old = _chainRoots[chainId];
            bytes32 newRoot = roots[i];
            if (newRoot != old) {
                _chainRoots[chainId] = newRoot;
                _chainUpdateTime[chainId] = block.timestamp;
                emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
            }
            unchecked { ++i; }
        }
        emit BatchChainRootsUpdated(msg.sender, len, block.timestamp);
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

    /**
     * @notice Return both roots and timestamps for multiple chainIds
     * @param chainIds Array of chain ids to query
     * @return roots Array of roots in same order as chainIds
     * @return times Array of timestamps corresponding to each chainId (0 if never set)
     */
    function getChainRootsAndUpdateTimes(uint256[] calldata chainIds)
        external
        view
        returns (bytes32[] memory roots, uint256[] memory times)
    {
        uint256 len = chainIds.length;
        roots = new bytes32[](len);
        times = new uint256[](len);
        for (uint256 i = 0; i < len; ) {
            uint256 id = chainIds[i];
            roots[i] = _chainRoots[id];
            times[i] = _chainUpdateTime[id];
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
        if (bytes(newName).length == 0) revert InvalidName();
        string memory oldName = _contractName;
        // Avoid emitting event if name is the same
        if (keccak256(bytes(oldName)) == keccak256(bytes(newName))) revert InvalidName();
        _contractName = newName;
        emit ContractRenamed(oldName, newName);
    }

    /**
     * @notice Renounce ownership (irreversible)
     */
    function renounceOwnership() external onlyOwner {
        address old = _owner;
        _owner = address(0);
        emit OwnershipTransferred(old, address(0));
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
        revert ETHNotAccepted();
    }

    fallback() external payable {
        revert InvalidName(); // reuse InvalidName as a neutral revert; or define another error if preferred
    }
}
