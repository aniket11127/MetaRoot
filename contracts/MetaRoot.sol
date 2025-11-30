// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title MetaRoot++
 * @notice Advanced, gas-optimized Merkle root registry with:
 *         - Global & chain-specific roots
 *         - Bounded ring-buffer history
 *         - Admin roles
 *         - Authorized signature-based updates
 *         - Batch root updates
 *         - EIP-712 domain separation
 *         - Pausing mechanism
 */
contract MetaRoot {
    // =========================================================
    //                      ERRORS
    // =========================================================
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

    // =========================================================
    //                   CONSTANTS
    // =========================================================
    uint256 public constant GLOBAL_HISTORY_LIMIT = 20;
    uint256 public constant CHAIN_HISTORY_LIMIT  = 50;

    bytes32 private constant ROOT_UPDATE_TYPEHASH =
        keccak256("RootUpdate(uint256 chainId,bytes32 newRoot,uint256 nonce)");

    // =========================================================
    //                       STATE
    // =========================================================
    address private _owner;
    uint256 private immutable _createdAt;

    string private _contractName;
    bool private _paused;

    bytes32 private _globalRoot;
    uint256 private _version;

    // Admins
    mapping(address => bool) private _admins;
    address[] private _adminList;
    mapping(address => uint256) private _adminIndex; // 1-based index

    // Signers
    mapping(address => bool) private _authorizedSigners;
    mapping(address => uint256) public nonces;

    // Chain roots
    mapping(uint256 => bytes32) private _chainRoots;
    mapping(uint256 => uint256) private _chainUpdateTime;

    // Global history (ring buffer)
    struct GlobalHistoryItem {
        bytes32 root;
        uint256 timestamp;
    }
    mapping(uint256 => GlobalHistoryItem) private _globalHistory;
    uint256 private _globalHistoryCount;

    // Chain history (ring buffers)
    struct ChainHistoryItem {
        bytes32 root;
        uint256 timestamp;
    }
    mapping(uint256 => mapping(uint256 => ChainHistoryItem)) private _chainHistory;
    mapping(uint256 => uint256) private _chainHistoryCount;

    // EIP-712 domain separator
    bytes32 private immutable _DOMAIN_SEPARATOR;

    // =========================================================
    //                       EVENTS
    // =========================================================
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event RenouncedOwnership(address indexed oldOwner);

    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);

    event AuthorizedSignerAdded(address indexed signer);
    event AuthorizedSignerRemoved(address indexed signer);

    event Paused();
    event Unpaused();

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

    event RootUpdatedBySig(
        address indexed signer,
        uint256 indexed chainId,
        bytes32 newRoot,
        uint256 nonce,
        uint256 timestamp
    );

    event ContractRenamed(string oldName, string newName);

    // =========================================================
    //                    MODIFIERS
    // =========================================================
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

    // =========================================================
    //                   CONSTRUCTOR
    // =========================================================
    constructor(string memory name_) {
        _owner = msg.sender;
        _createdAt = block.timestamp;
        _version = 1;

        _contractName = bytes(name_).length == 0 ? "MetaRoot++" : name_;

        emit OwnershipTransferred(address(0), msg.sender);

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

    // =========================================================
    //                   OWNER FUNCTIONS
    // =========================================================
    function owner() external view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function renounceOwnership() external onlyOwner {
        address old = _owner;
        _owner = address(0);
        emit RenouncedOwnership(old);
        emit OwnershipTransferred(old, address(0));
    }

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

    // =========================================================
    //                   ADMIN MANAGEMENT
    // =========================================================
    function addAdmin(address admin) external onlyOwner {
        if (admin == address(0)) revert ZeroAddress();
        if (_admins[admin]) return;

        _admins[admin] = true;
        _adminList.push(admin);
        _adminIndex[admin] = _adminList.length;

        emit AdminAdded(admin);
    }

    function removeAdmin(address admin) external onlyOwner {
        if (!_admins[admin]) return;

        uint256 idx = _adminIndex[admin];
        uint256 last = _adminList.length;

        if (idx != last) {
            address lastAdmin = _adminList[last - 1];
            _adminList[idx - 1] = lastAdmin;
            _adminIndex[lastAdmin] = idx;
        }

        _adminList.pop();
        delete _admins[admin];
        delete _adminIndex[admin];

        emit AdminRemoved(admin);
    }

    function getAdmins() external view returns (address[] memory) {
        return _adminList;
    }

    function adminCount() external view returns (uint256) {
        return _adminList.length;
    }

    // =========================================================
    //                 AUTHORIZED SIGNERS
    // =========================================================
    function addAuthorizedSigner(address signer) external onlyOwner {
        if (signer == address(0)) revert ZeroAddress();

        if (!_authorizedSigners[signer]) {
            _authorizedSigners[signer] = true;
            emit AuthorizedSignerAdded(signer);
        }
    }

    function removeAuthorizedSigner(address signer) external onlyOwner {
        if (_authorizedSigners[signer]) {
            delete _authorizedSigners[signer];
            emit AuthorizedSignerRemoved(signer);
        }
    }

    function isAuthorizedSigner(address signer) external view returns (bool) {
        return _authorizedSigners[signer];
    }

    // =========================================================
    //                       PAUSE
    // =========================================================
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

    // =========================================================
    //              GLOBAL ROOT + HISTORY (RING BUFFER)
    // =========================================================
    function getGlobalRoot() external view returns (bytes32) {
        return _globalRoot;
    }

    function getGlobalVersion() external view returns (uint256) {
        return _version;
    }

    function setGlobalRoot(bytes32 newRoot)
        external
        onlyAdminOrOwner
        whenNotPaused
    {
        bytes32 old = _globalRoot;
        if (newRoot == old) revert SameRoot();

        _globalRoot = newRoot;
        unchecked { _version++; }

        uint256 cnt = ++_globalHistoryCount;
        uint256 pos = (cnt - 1) % GLOBAL_HISTORY_LIMIT;
        _globalHistory[pos] = GlobalHistoryItem(newRoot, block.timestamp);

        emit GlobalRootUpdated(msg.sender, old, newRoot, _version, block.timestamp);
    }

    function getGlobalHistoryLast(uint256 maxItems)
        external
        view
        returns (GlobalHistoryItem[] memory items)
    {
        if (maxItems == 0) return new GlobalHistoryItem;
        if (maxItems > GLOBAL_HISTORY_LIMIT) revert ExceedsLimit();

        uint256 total = _globalHistoryCount;
        uint256 available = total > GLOBAL_HISTORY_LIMIT ? GLOBAL_HISTORY_LIMIT : total;
        uint256 take = maxItems < available ? maxItems : available;

        items = new GlobalHistoryItem[](take);
        if (take == 0) return items;

        uint256 pos = (total - 1) % GLOBAL_HISTORY_LIMIT;

        for (uint256 i; i < take; ) {
            items[i] = _globalHistory[pos];
            pos = pos == 0 ? GLOBAL_HISTORY_LIMIT - 1 : pos - 1;
            unchecked { i++; }
        }
    }

    // =========================================================
    //          CHAIN ROOTS + HISTORY (RING BUFFER)
    // =========================================================
    function setChainRoot(uint256 chainId, bytes32 newRoot)
        public
        onlyAdminOrOwner
        whenNotPaused
    {
        bytes32 old = _chainRoots[chainId];
        if (newRoot == old) revert SameRoot();

        _chainRoots[chainId] = newRoot;
        _chainUpdateTime[chainId] = block.timestamp;

        uint256 cnt = ++_chainHistoryCount[chainId];
        uint256 pos = (cnt - 1) % CHAIN_HISTORY_LIMIT;

        _chainHistory[chainId][pos] = ChainHistoryItem(newRoot, block.timestamp);

        emit ChainRootUpdated(msg.sender, chainId, old, newRoot, block.timestamp);
    }

    function batchSetChainRoots(uint256[] calldata chainIds, bytes32[] calldata roots)
        external
        onlyAdminOrOwner
        whenNotPaused
    {
        uint256 len = chainIds.length;
        if (len != roots.length) revert ArrayLengthMismatch();

        for (uint256 i; i < len; ) {
            setChainRoot(chainIds[i], roots[i]);
            unchecked { ++i; }
        }

        emit BatchChainRootsUpdated(msg.sender, len, block.timestamp);
    }

    function getChainRoot(uint256 chainId) external view returns (bytes32) {
        return _chainRoots[chainId];
    }

    function getChainUpdateTime(uint256 chainId) external view returns (uint256) {
        return _chainUpdateTime[chainId];
    }

    function getChainRoots(uint256[] calldata chainIds)
        external
        view
        returns (bytes32[] memory roots)
    {
        uint256 len = chainIds.length;
        roots = new bytes32[](len);

        for (uint256 i; i < len; ) {
            roots[i] = _chainRoots[chainIds[i]];
            unchecked { ++i; }
        }
    }

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
        if (take == 0) return items;

        uint256 pos = (total - 1) % CHAIN_HISTORY_LIMIT;

        for (uint256 i; i < take; ) {
            items[i] = _chainHistory[chainId][pos];
            pos = pos == 0 ? CHAIN_HISTORY_LIMIT - 1 : pos - 1;
            unchecked { ++i; }
        }
    }

    // =========================================================
    //         EIP-712 SIGNATURE-BASED UPDATES
    // =========================================================
    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
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
                _DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(ROOT_UPDATE_TYPEHASH, chainId, newRoot, nonce)
                )
            )
        );

        address signer = _recover(digest, signature);

        if (signer != _owner && !_authorizedSigners[signer]) revert InvalidSignature();
        if (nonce != nonces[signer]++) revert InvalidSignature();

        setChainRoot(chainId, newRoot);

        emit RootUpdatedBySig(signer, chainId, newRoot, nonce, block.timestamp);
    }

    function verifySigner(bytes32 digest, bytes calldata sig)
        external
        pure
        returns (address)
    {
        return _recover(digest, sig);
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

    // =========================================================
    //                     METADATA
    // =========================================================
    function renameContract(string calldata newName) external onlyOwner {
        if (bytes(newName).length == 0) revert InvalidName();
        string memory old = _contractName;
        _contractName = newName;
        emit ContractRenamed(old, newName);
    }

    // =========================================================
    //                     FALLBACKS
    // =========================================================
    receive() external payable { revert ETHNotAccepted(); }
    fallback() external payable { revert(); }
}
