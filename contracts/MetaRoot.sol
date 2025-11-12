// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MetaRoot {

    struct RootIdentity {
        address owner;
        address[] linkedAddresses;
        bool exists;
    }

    // Each user can create **one** root identity
    mapping(address => RootIdentity) public roots;

    event RootCreated(address indexed owner);
    event AddressLinked(address indexed owner, address indexed linked);

    /**
     * @notice Create a root identity for the caller.
     *        Can only be created once.
     */
    function createRoot() external {
        require(!roots[msg.sender].exists, "Root already exists");

        roots[msg.sender].owner = msg.sender;
        roots[msg.sender].exists = true;

        emit RootCreated(msg.sender);
    }

    /**
     * @notice Link another wallet address to your root identity.
     * @param wallet Address to link under your identity.
     */
    function linkAddress(address wallet) external {
        require(roots[msg.sender].exists, "Root not created");
        require(wallet != address(0), "Invalid address");

        roots[msg.sender].linkedAddresses.push(wallet);

        emit AddressLinked(msg.sender, wallet);
    }

    /**
     * @notice View linked addresses for a root identity owner.
     * @param owner The root owner.
     */
    function getLinkedAddresses(address owner) external view returns (address[] memory) {
        return roots[owner].linkedAddresses;
    }
}
