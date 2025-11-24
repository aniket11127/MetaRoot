// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot++
 * @notice Advanced Merkle root registry with history, pausing, roles & EIP-712 support.
 * @dev Adds admin enumeration, authorized signers, bounded per-chain ring-buffer history,
 * batch updates, ownership transfer and helpful getters.
 */
contract MetaRoot {
    // ------------------------------------------------------------------------
    // ERRORS
    // ------------------------------------------------------------------------
    error NotOwner();
    error NotAdminOrOwner();
    error ZeroAddress();
    error SameRoot();
    error ETHNotAccepted();
    error InvalidName();
    error Paused();
    error InvalidSignature();
    error ArrayLengthMismatch();
    error ExceedsLimit();

    // ------------------------------------------------------------------------
    // STATE
    // ------------------------------------------------------------------------
    address private _owner;
    uint256 private immutable _createdAt;

    // Admin management (mapping + list for enumeration)
    mapping(address => bool) private _admins;
    address[] private _adminList;
    mapping(address => uint256) private _adminIndex; // 1-based index in _adminList (0 means not present)

    bool private _paused;

    string private _contractName;

    bytes32 private _globalRoot;
    uint256 private _version;

    mapping(uint256 => bytes32) private _chainRoots;
    mapping(uint256 => uint256) private _chainUpdateTime;

    // ------------------------------------------------------------------------
    // ROOT HISTORY (per-chain ring buffer)
    // ------------------------------------------------------------------------
    uint256 public constant GLOBAL_HISTORY_LIMIT = 20;
    uint256 public constant CHAIN_HISTORY_LIMIT = 50; // configurable constant

    struct GlobalHistory {
        bytes32 root;
        uint256 timestamp;
    }
    GlobalHistory[] private _globalHistory;

    struct ChainHistoryItem {
        bytes32 root;
        uint256 timestamp;
    }
    // ring buffer storage: chainId => index => item
    mapping(uint256 => mapping(uint256 => ChainHistoryItem)) private _chainHistoryEntries;
    // chainId => total pushes (monotonic)
    mapping(uint256 => uint256) private _chainHistoryCount;

    // ------------------------------------------------------------------------
    // EIP-712
    // ------------------------------------------------------------------------
    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 private constant ROOT_UPDATE_TYPEHASH =
        keccak256("RootUpdate(uint256 chainId,bytes32 newRoot,uint256 nonce)");

    mapping(address => uint256) public nonces;

    // authorized signers (in addition to owner)
    mapping(address => bool) private _authorizedSigners;

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

    event BatchChainRootsUpdated(address indexed updater, uint256 count, uint256 timestamp);

    event AuthorizedSignerAdded(address signer);
    event AuthorizedSignerRemoved(address signer);

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

        _contractName = bytes(name_).length == 0 ? "MetaRoot++" : name_;

        emit OwnershipTransferred(address(0), msg.sender);

        // Pre-calc domain separator once (EIP-712)
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(_contractName)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    // ------------------------------------------------------------------------
    // OWNERSHIP
    // ------------------------------------------------------------------------

    /// @notice Transfer ownership to a new owner (non-zero)
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address old = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(old, newOwner);
    }

    /// @notice Get contract detail summary
    function getContractDetails()
        external
        view
        returns (
            string memory name_,
            address owner_,
            uint256 version_,
            uint256 createdAt_,
            bytes32 globalRoot_
        )
    {
        return (_contractName, _owner, _version, _createdAt, _globalRoot);
    }

    // ------------------------------------------------------------------------
    // ADMIN MANAGEMENT (enumerable)
    // ------------------------------------------------------------------------

    /// @notice Add an admin (owner only)
    function addAdmin(address admin) external onlyOwner {
        if (admin == address(0)) revert ZeroAddress();
        if (!_admins[admin]) {
            _admins[admin] = true;
            _adminList.push(admin);
            _adminIndex[admin] = _adminList.length; // 1-based
            emit AdminAdded(admin);
        }
    }

    /// @notice Remove an admin (owner only)
    function removeAdmin(address admin) external onlyOwner {
        if (_admins[admin]) {
            // swap-pop from _adminList
            uint256 idx = _adminIndex[admin];
            if (idx == 0) return; // defensive
            uint256 lastIdx = _adminList.length;
            address lastAdmin = _adminList[lastIdx - 1];

            if (idx != lastIdx) {
                // replace
                _adminList[idx - 1] = lastAdmin;
                _adminIndex[lastAdmin] = idx;
            }
            _adminList.pop();
            delete _adminIndex[admin];
            delete _admins[admin];
            emit AdminRemoved(admin);
        }
    }

    /// @notice Return the current admin list (snapshot)
    function getAdmins() external view returns (address[] memory) {
        return _adminList;
    }

    /// @notice Check whether address is admin
    function isAdmin(address addr) external view returns (bool) {
        return _admins[addr];
    }

    // ------------------------------------------------------------------------
    // AUTHORIZED SIGNERS
    // ------------------------------------------------------------------------

    /// @notice Add an authorized signer (owner only)
    function addAuthorizedSigner(address signer) external onlyOwner {
        if (signer == address(0)) revert ZeroAddress();
        if (!_authorizedSigners[signer]) {
            _authorizedSigners[signer] = true;
            emit AuthorizedSignerAdded(signer);
        }
    }

    /// @notice Remove an authorized signer (owner only)
    function removeAuthorizedSigner(address signer) external onlyOwner {
        if (_authorizedSigners[signer]) {
            delete _authorizedSigners[signer];
            emit AuthorizedSignerRemoved(signer);
        }
    }

    /// @notice Check authorized signer
    function isAuthorizedSigner(address signer) external view returns (bool) {
        return _authorizedSigners[signer];
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
        public
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
        if (_globalHistory.length == GLOBAL_HISTORY_LIMIT) {
            // shift-left by one: move [1..n-1] -> [0..n-2], set last
            for (uint256 i = 0; i < GLOBAL_HISTORY_LIMIT - 1; ) {
                _globalHistory[i] = _globalHistory[i + 1];
                unchecked { i++; }
            }
            _globalHistory[GLOBAL_HISTORY_LIMIT - 1] = GlobalHistory(root, block.timestamp);
        } else {
            _globalHistory.push(GlobalHistory(root, block.timestamp));
        }
    }

    function getGlobalHistory() external view returns (GlobalHistory[] memory) {
        return _globalHistory;
    }

    // ------------------------------------------------------------------------
    // CHAIN ROOT (single + batch + bounded history)
    // ------------------------------------------------------------------------

    /// @notice Set a single chain root
    function setChainRoot(uint256 chainId, bytes32 newRoot)
        public
        onlyAdminOrOwner
        whenNotPaused
    {
        bytes32 old = _chainRoots[chainId];
        if (newRoot == old) revert SameRoot();

        _chainRoots[chainId] = newRoot;
        _chainUpdateTime[chainId] = block.timestamp;

        // push into ring buffer at index = count % CHAIN_HISTORY_LIMIT
        uint256 count = ++_chainHistoryCount[chainId];
        uint256 idx = (count - 1) % CHAIN_HISTORY_LIMIT;
        _chainHistoryEntries[chainId][idx] = ChainHistoryItem(newRoot, block.timestamp);

        emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
    }

    /// @notice Batch set chain roots
    function batchSetChainRoots(uint256[] calldata chainIds, bytes32[] calldata roots)
        external
        onlyAdminOrOwner
        whenNotPaused
    {
        uint256 len = chainIds.length;
        if (len != roots.length) revert ArrayLengthMismatch();
        for (uint256 i = 0; i < len; ) {
            setChainRoot(chainIds[i], roots[i]); // reuses single setter & events
            unchecked { i++; }
        }
        emit BatchChainRootsUpdated(msg.sender, len, block.timestamp);
    }

    /// @notice Get current root for a chain
    function getChainRoot(uint256 chainId) external view returns (bytes32) {
        return _chainRoots[chainId];
    }

    /// @notice Get last update timestamp for a chain
    function getChainUpdateTime(uint256 chainId) external view returns (uint256) {
        return _chainUpdateTime[chainId];
    }

    /// @notice Batch getter for multiple chain roots
    function getChainRoots(uint256[] calldata chainIds) external view returns (bytes32[] memory roots) {
        uint256 len = chainIds.length;
        roots = new bytes32[](len);
        for (uint256 i = 0; i < len; ) {
            roots[i] = _chainRoots[chainIds[i]];
            unchecked { i++; }
        }
    }

    /// @notice Return last up to `maxItems` chain history entries (newest-first)
    /// @dev maxItems cannot exceed CHAIN_HISTORY_LIMIT
    function getChainHistoryLast(uint256 chainId, uint256 maxItems)
        external
        view
        returns (ChainHistoryItem[] memory items)
    {
        if (maxItems == 0) return new ChainHistoryItem;
        if (maxItems > CHAIN_HISTORY_LIMIT) revert ExceedsLimit();

        uint256 total = _chainHistoryCount[chainId];
        uint256 available = total > CHAIN_HISTORY_LIMIT ? CHAIN_HISTORY_LIMIT : total;
        uint256 take = maxItems < available ? maxItems : available;

        items = new ChainHistoryItem[](take);
        // start from most recent: index = (total - 1) % limit, then go backwards
        uint256 idx;
        if (available == 0) return items;

        uint256 latestPos = (total == 0) ? 0 : (total - 1) % CHAIN_HISTORY_LIMIT;
        uint256 pos = latestPos;

        for (uint256 i = 0; i < take; ) {
            items[i] = _chainHistoryEntries[chainId][pos];
            // decrement pos with wrap
            if (pos == 0) pos = CHAIN_HISTORY_LIMIT - 1;
            else pos = pos - 1;
            unchecked { i++; }
        }
    }

    // ------------------------------------------------------------------------
    // EIP-712 SIGN-BASED UPDATES (meta-transactions)
    // ------------------------------------------------------------------------

    /// @notice Return the precalculated domain separator
    function domainSeparator() public view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    /// @notice Update a chain root using a signature from owner OR an authorized signer
    function updateChainRootBySig(
        uint256 chainId,
        bytes32 newRoot,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _DOMAIN_SEPARATOR,
                keccak256(abi.encode(ROOT_UPDATE_TYPEHASH, chainId, newRoot, nonce))
            )
        );

        address signer = _recover(digest, signature);
        // accept owner or any authorized signer
        if (signer != _owner && !_authorizedSigners[signer]) revert InvalidSignature();

        if (nonce != nonces[signer]++) revert InvalidSignature();

        setChainRoot(chainId, newRoot);
    }

    /// @notice Public helper to recover signer from digest + signature
    function verifySigner(bytes32 digest, bytes calldata signature) external pure returns (address) {
        return _recover(digest, signature);
    }

    function _recover(bytes32 hash, bytes memory sig)
        internal
        pure
        returns (address signer)
    {
        if (sig.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
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
