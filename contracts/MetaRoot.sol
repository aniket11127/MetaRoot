// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot
 * @notice A decentralized smart contract for storing and managing global & chain-specific Merkle roots.
 * @dev Built with ownership, versioning, and event transparency. Suitable for multi-chain metadata sync.
 * @author 
 *  MetaRoot Protocol — Built with ❤️ for decentralized ecosystems
 */

contract MetaRoot {
    // ------------------------------------------------------------------------
    // STATE VARIABLES
    // ------------------------------------------------------------------------

    address private _owner;                // Contract owner
    bytes32 private _globalRoot;           // Global root (e.g., metadata or Merkle root)
    uint256 private _version;              // Version counter for global updates
    uint256 private _createdAt;            // Contract creation timestamp
    string private _contractName;          // Optional label for UI or tracking

    // Mapping for chain-specific roots (chainId => root)
    mapping(uint256 => bytes32) private _chainRoots;

    // Mapping for last update timestamps per chain
    mapping(uint256 => uint256) private _chainUpdateTime;

    // ------------------------------------------------------------------------
    // EVENTS
    // ------------------------------------------------------------------------

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event GlobalRootUpdated(address indexed updater, bytes32 oldRoot, bytes32 newRoot, uint256 version, uint256 timestamp);
    event ChainRootUpdated(address indexed updater, uint256 indexed chainId, bytes32 oldRoot, bytes32 newRoot, uint256 timestamp);
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
     * @notice Initializes the contract with an optional name.
     * @param name_ Optional name for the contract (e.g., “MetaRoot Main”)
     */
    constructor(string memory name_) {
        _owner = msg.sender;
        _version = 1;
        _createdAt = block.timestamp;
        _contractName = bytes(name_).length > 0 ? name_ : "MetaRoot";
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ------------------------------------------------------------------------
    // OWNERSHIP FUNCTIONS
    // ------------------------------------------------------------------------

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "MetaRoot: new owner is zero address");
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    // ------------------------------------------------------------------------
    // GLOBAL ROOT FUNCTIONS
    // ------------------------------------------------------------------------

    function getGlobalRoot() external view returns (bytes32) {
        return _globalRoot;
    }

    function getGlobalVersion() external view returns (uint256) {
        return _version;
    }

    function getContractAge() external view returns (uint256) {
        return block.timestamp - _createdAt;
    }

    /**
     * @notice Sets or updates the global root value.
     * @param newRoot New global Merkle or metadata root.
     */
    function setGlobalRoot(bytes32 newRoot) external onlyOwner {
        bytes32 old = _globalRoot;
        _globalRoot = newRoot;
        _version += 1;
        emit GlobalRootUpdated(msg.sender, old, newRoot, _version, block.timestamp);
    }

    // ------------------------------------------------------------------------
    // CHAIN ROOT FUNCTIONS
    // ------------------------------------------------------------------------

    function getChainRoot(uint256 chainId) external view returns (bytes32) {
        return _chainRoots[chainId];
    }

    function getChainUpdateTime(uint256 chainId) external view returns (uint256) {
        return _chainUpdateTime[chainId];
    }

    /**
     * @notice Sets or updates the root for a specific chain ID.
     * @param chainId The target chain’s unique identifier.
     * @param newRoot The new root to assign.
     */
    function setChainRoot(uint256 chainId, bytes32 newRoot) external onlyOwner {
        bytes32 old = _chainRoots[chainId];
        _chainRoots[chainId] = newRoot;
        _chainUpdateTime[chainId] = block.timestamp;
        emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
    }

    /**
     * @notice Batch update multiple chain roots in one transaction.
     * @param chainIds Array of chain IDs.
     * @param roots Array of new roots corresponding to each chain.
     */
    function batchSetChainRoots(uint256[] calldata chainIds, bytes32[] calldata roots) external onlyOwner {
        require(chainIds.length == roots.length, "MetaRoot: array length mismatch");

        for (uint256 i = 0; i < chainIds.length; i++) {
            uint256 chainId = chainIds[i];
            bytes32 old = _chainRoots[chainId];
            _chainRoots[chainId] = roots[i];
            _chainUpdateTime[chainId] = block.timestamp;

            emit ChainRootUpdated(msg.sender, chainId, old, roots[i], block.timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // CONTRACT INFO FUNCTIONS
    // ------------------------------------------------------------------------

    function getContractName() external view returns (string memory) {
        return _contractName;
    }

    function renameContract(string calldata newName) external onlyOwner {
        string memory oldName = _contractName;
        _contractName = newName;
        emit ContractRenamed(oldName, newName);
    }

    // ------------------------------------------------------------------------
    // SAFETY & UTILITY
    // ------------------------------------------------------------------------

    /**
     * @notice Emergency function to renounce ownership.
     * @dev Once called, contract becomes ownerless — irreversible.
     */
    function renounceOwnership() external onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @notice Returns metadata about the contract.
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

    /**
     * @notice Verifies whether a given address is the owner.
     */
    function isOwner(address addr) external view returns (bool) {
        return addr == _owner;
    }

    /**
     * @notice Fallback and receive functions to prevent accidental ETH transfers.
     */
    receive() external payable {
        revert("MetaRoot: direct ETH not accepted");
    }

    fallback() external payable {
        revert("MetaRoot: invalid call");
    }
}
