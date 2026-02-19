// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title SigilumRegistry
 * @notice On-chain registry for agent identity claims.
 * @dev Namespaces map human identities to wallet addresses.
 *      Claims link agent public keys to namespaces for specific services.
 *      Only the namespace owner can approve, reject, or revoke claims.
 */
contract SigilumRegistry {
    // ─── Types ───────────────────────────────────────────────────────────────

    enum ClaimStatus {
        Pending,
        Approved,
        Revoked,
        Rejected,
        Expired
    }

    struct Namespace {
        address owner;
        bool active;
        uint256 createdAt;
    }

    struct Claim {
        string namespace;
        bytes publicKey;
        string service;
        string agentIP;
        ClaimStatus status;
        uint256 createdAt;
        uint256 resolvedAt;
    }

    struct Service {
        string name;
        string namespace;
        string website;
        string description;
        string[] tags;
        uint256 registeredAt;
        uint256 updatedAt;
    }

    // ─── State ───────────────────────────────────────────────────────────────

    /// @notice Sigilum relayer address (can register services and namespaces on behalf of users)
    address public sigilumRelayer;

    /// @notice Namespace name → Namespace data
    mapping(string => Namespace) public namespaces;

    /// @notice Claim ID → Claim data
    mapping(bytes32 => Claim) public claims;

    /// @notice Namespace → array of claim IDs (for enumeration)
    mapping(string => bytes32[]) public namespaceClaims;

    /// @notice Rate limiting: namespace → pending claim count
    mapping(string => uint256) public pendingClaimCount;

    /// @notice O(1) authorization lookup: keccak256(namespace, publicKey, service) → approved
    mapping(bytes32 => bool) private _approvedClaims;

    /// @notice Service namespace → Service data
    mapping(string => Service) public services;

    /// @notice Array of all service namespaces (for enumeration)
    string[] public serviceList;

    /// @notice Maximum pending claims per namespace
    uint256 public constant MAX_PENDING_CLAIMS = 20;

    /// @notice Claim expiry duration (pending claims expire after 24 hours)
    uint256 public constant CLAIM_EXPIRY = 24 hours;

    // ─── Events ──────────────────────────────────────────────────────────────

    event RelayerTransferred(address indexed from, address indexed to);

    event NamespaceRegistered(string indexed name, address indexed owner);
    event NamespaceTransferred(string indexed name, address indexed from, address indexed to);

    event ServiceRegistered(string indexed namespace, string name, string website);
    event ServiceUpdated(string indexed namespace, string name, string website);

    event ClaimSubmitted(
        bytes32 indexed claimId,
        string indexed namespace,
        bytes publicKey,
        string service,
        string agentIP
    );

    event ClaimApproved(bytes32 indexed claimId, string indexed namespace, string service);
    event ClaimRevoked(bytes32 indexed claimId, string indexed namespace, string service);
    event ClaimRejected(bytes32 indexed claimId, string indexed namespace);
    event ExpiredClaimsCleaned(string indexed namespace, uint256 count);

    // ─── Errors ──────────────────────────────────────────────────────────────

    error InvalidNameLength();
    error NamespaceTaken();
    error NotNamespaceOwner();
    error InvalidAddress();
    error NamespaceNotActive();
    error TooManyPendingClaims();
    error ClaimNotPending();
    error ClaimExpired();
    error ClaimNotApproved();
    error ClaimAlreadyExists();
    error UnexpectedClaimStatus();
    error OnlySigilumRelayer();
    error RelayerTransferToZeroAddress();
    error ServiceNamespaceTaken();
    error ServiceNotFound();

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor() {
        sigilumRelayer = msg.sender;
    }

    // ─── Relayer Management ──────────────────────────────────────────────────

    /// @notice Transfer the relayer role to a new address. Only the current relayer can call this.
    /// @param newRelayer The address of the new relayer
    function transferRelayer(address newRelayer) external {
        if (msg.sender != sigilumRelayer) revert OnlySigilumRelayer();
        if (newRelayer == address(0)) revert RelayerTransferToZeroAddress();

        address oldRelayer = sigilumRelayer;
        sigilumRelayer = newRelayer;

        emit RelayerTransferred(oldRelayer, newRelayer);
    }

    // ─── Service Management ──────────────────────────────────────────────────

    /// @notice Register a new service (Sigilum-only)
    /// @param name The service display name (e.g., "Acme Bank")
    /// @param namespace The service namespace/slug (e.g., "acmebank")
    /// @param website The service website URL
    /// @param description Short description for discovery
    /// @param tags Tags for categorization and discovery
    function registerService(
        string calldata name,
        string calldata namespace,
        string calldata website,
        string calldata description,
        string[] calldata tags
    ) external {
        if (msg.sender != sigilumRelayer) revert OnlySigilumRelayer();

        // Validate namespace format (same rules as user namespaces)
        uint256 len = bytes(namespace).length;
        if (len < 3 || len > 64) revert InvalidNameLength();

        // Check if namespace is already taken
        if (bytes(services[namespace].namespace).length != 0) {
            revert ServiceNamespaceTaken();
        }

        services[namespace] = Service({
            name: name,
            namespace: namespace,
            website: website,
            description: description,
            tags: tags,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp
        });

        serviceList.push(namespace);

        emit ServiceRegistered(namespace, name, website);
    }

    /// @notice Update an existing service (Sigilum-only)
    /// @param namespace The service namespace to update
    /// @param name New service name
    /// @param website New website URL
    /// @param description New description
    /// @param tags New tags
    function updateService(
        string calldata namespace,
        string calldata name,
        string calldata website,
        string calldata description,
        string[] calldata tags
    ) external {
        if (msg.sender != sigilumRelayer) revert OnlySigilumRelayer();

        // Check if service exists
        if (bytes(services[namespace].namespace).length == 0) {
            revert ServiceNotFound();
        }

        Service storage service = services[namespace];
        service.name = name;
        service.website = website;
        service.description = description;
        service.tags = tags;
        service.updatedAt = block.timestamp;

        emit ServiceUpdated(namespace, name, website);
    }

    /// @notice Get all registered service namespaces
    /// @return Array of service namespaces
    function getServiceList() external view returns (string[] memory) {
        return serviceList;
    }

    /// @notice Get service details
    /// @param namespace The service namespace
    /// @return The service data
    function getService(string calldata namespace)
        external
        view
        returns (Service memory)
    {
        if (bytes(services[namespace].namespace).length == 0) {
            revert ServiceNotFound();
        }
        return services[namespace];
    }

    // ─── Namespace Management ────────────────────────────────────────────────

    /// @notice Register a new namespace. Caller becomes the owner.
    /// @param name The namespace name (3–64 characters)
    function registerNamespace(string calldata name) external {
        uint256 len = bytes(name).length;
        if (len < 3 || len > 64) revert InvalidNameLength();
        if (namespaces[name].owner != address(0)) revert NamespaceTaken();

        namespaces[name] =
            Namespace({owner: msg.sender, active: true, createdAt: block.timestamp});

        emit NamespaceRegistered(name, msg.sender);
    }

    /// @notice Transfer namespace ownership to a new wallet.
    /// @param name The namespace to transfer
    /// @param newOwner The new owner address
    function transferNamespace(string calldata name, address newOwner) external {
        if (msg.sender != namespaces[name].owner) revert NotNamespaceOwner();
        if (newOwner == address(0)) revert InvalidAddress();

        address oldOwner = namespaces[name].owner;
        namespaces[name].owner = newOwner;

        emit NamespaceTransferred(name, oldOwner, newOwner);
    }

    // ─── Claim Management ────────────────────────────────────────────────────

    /// @notice Submit a new claim. Anyone can submit (typically the service on behalf of the agent).
    /// @param namespace The target namespace
    /// @param publicKey The agent's Ed25519 public key
    /// @param service The service identifier
    /// @param agentIP The agent's IP address for human verification
    /// @return claimId The unique claim identifier
    function submitClaim(
        string calldata namespace,
        bytes calldata publicKey,
        string calldata service,
        string calldata agentIP
    ) external returns (bytes32) {
        if (!namespaces[namespace].active) revert NamespaceNotActive();

        // Deterministic claim ID based on (namespace, publicKey, service)
        bytes32 claimId = keccak256(abi.encode(namespace, publicKey, service));

        // Check for claim ID collision: revert if existing claim is Pending or Approved
        bool isNewClaim = claims[claimId].createdAt == 0;
        if (!isNewClaim) {
            ClaimStatus existingStatus = claims[claimId].status;
            if (existingStatus == ClaimStatus.Pending) {
                // Check if the pending claim has expired
                if (block.timestamp - claims[claimId].createdAt <= CLAIM_EXPIRY) {
                    revert ClaimAlreadyExists();
                }
                // Expired pending claim — allow re-request, decrement counter
                pendingClaimCount[namespace]--;
            } else if (existingStatus == ClaimStatus.Approved) {
                revert ClaimAlreadyExists();
            } else if (existingStatus == ClaimStatus.Rejected) {
                // Rejected — allow re-request
            } else if (existingStatus == ClaimStatus.Revoked) {
                // Revoked — allow re-request
            } else if (existingStatus == ClaimStatus.Expired) {
                // Expired (cleaned by cleanExpiredClaims) — allow re-request
            } else {
                revert UnexpectedClaimStatus();
            }
        }

        // Check pending claim limit (after handling expired claim above)
        if (pendingClaimCount[namespace] >= MAX_PENDING_CLAIMS) {
            revert TooManyPendingClaims();
        }

        claims[claimId] = Claim({
            namespace: namespace,
            publicKey: publicKey,
            service: service,
            agentIP: agentIP,
            status: ClaimStatus.Pending,
            createdAt: block.timestamp,
            resolvedAt: 0
        });

        // Only push to namespaceClaims if this is a new claim ID
        if (isNewClaim) {
            namespaceClaims[namespace].push(claimId);
        }
        pendingClaimCount[namespace]++;

        emit ClaimSubmitted(claimId, namespace, publicKey, service, agentIP);
        return claimId;
    }

    /// @notice Approve a pending claim. Only the namespace owner can call this.
    /// @param claimId The claim to approve
    function approveClaim(bytes32 claimId) external {
        Claim storage claim = claims[claimId];
        if (msg.sender != namespaces[claim.namespace].owner) {
            revert NotNamespaceOwner();
        }
        if (claim.status != ClaimStatus.Pending) revert ClaimNotPending();
        if (block.timestamp - claim.createdAt > CLAIM_EXPIRY) revert ClaimExpired();

        claim.status = ClaimStatus.Approved;
        claim.resolvedAt = block.timestamp;
        pendingClaimCount[claim.namespace]--;

        // Set O(1) authorization lookup
        bytes32 authKey = keccak256(abi.encode(claim.namespace, claim.publicKey, claim.service));
        _approvedClaims[authKey] = true;

        emit ClaimApproved(claimId, claim.namespace, claim.service);
    }

    /// @notice Reject a pending claim. Only the namespace owner can call this.
    /// @param claimId The claim to reject
    function rejectClaim(bytes32 claimId) external {
        Claim storage claim = claims[claimId];
        if (msg.sender != namespaces[claim.namespace].owner) {
            revert NotNamespaceOwner();
        }
        if (claim.status != ClaimStatus.Pending) revert ClaimNotPending();

        claim.status = ClaimStatus.Rejected;
        claim.resolvedAt = block.timestamp;
        pendingClaimCount[claim.namespace]--;

        emit ClaimRejected(claimId, claim.namespace);
    }

    /// @notice Revoke an approved claim. Only the namespace owner can call this.
    /// @param claimId The claim to revoke
    function revokeClaim(bytes32 claimId) external {
        Claim storage claim = claims[claimId];
        if (msg.sender != namespaces[claim.namespace].owner) {
            revert NotNamespaceOwner();
        }
        if (claim.status != ClaimStatus.Approved) revert ClaimNotApproved();

        claim.status = ClaimStatus.Revoked;
        claim.resolvedAt = block.timestamp;

        // Clear O(1) authorization lookup
        bytes32 authKey = keccak256(abi.encode(claim.namespace, claim.publicKey, claim.service));
        _approvedClaims[authKey] = false;

        emit ClaimRevoked(claimId, claim.namespace, claim.service);
    }

    // ─── Direct Approval/Revocation (API Mode) ──────────────────────────────

    /// @notice Approve a claim directly without submitting it first (for API mode).
    /// @dev Creates and approves a claim in one transaction, skipping pending state.
    ///      Saves gas and eliminates the need for two separate transactions.
    /// @param namespace The target namespace
    /// @param publicKey The agent's Ed25519 public key
    /// @param service The service identifier
    /// @param agentIP The agent's IP address for human verification
    /// @return claimId The unique claim identifier
    function approveClaimDirect(
        string calldata namespace,
        bytes calldata publicKey,
        string calldata service,
        string calldata agentIP
    ) external returns (bytes32) {
        if (msg.sender != namespaces[namespace].owner) revert NotNamespaceOwner();
        if (!namespaces[namespace].active) revert NamespaceNotActive();

        // Deterministic claim ID based on (namespace, publicKey, service)
        bytes32 claimId = keccak256(abi.encode(namespace, publicKey, service));

        // Check if claim already exists and handle accordingly
        bool isNewClaim = claims[claimId].createdAt == 0;
        if (!isNewClaim) {
            ClaimStatus existingStatus = claims[claimId].status;
            // Allow re-approval if previously rejected, revoked, or expired
            if (existingStatus == ClaimStatus.Approved) {
                revert ClaimAlreadyExists();
            }
            if (existingStatus == ClaimStatus.Pending) {
                // Existing pending claim - decrement counter before approving
                pendingClaimCount[namespace]--;
            }
            // For Rejected, Revoked, or Expired: allow re-approval
        }

        // Create and approve in one step
        claims[claimId] = Claim({
            namespace: namespace,
            publicKey: publicKey,
            service: service,
            agentIP: agentIP,
            status: ClaimStatus.Approved,
            createdAt: isNewClaim ? block.timestamp : claims[claimId].createdAt,
            resolvedAt: block.timestamp
        });

        // Add to namespace claims array if this is a new claim ID
        if (isNewClaim) {
            namespaceClaims[namespace].push(claimId);
        }

        // Set O(1) authorization lookup
        bytes32 authKey = keccak256(abi.encode(namespace, publicKey, service));
        _approvedClaims[authKey] = true;

        emit ClaimApproved(claimId, namespace, service);
        return claimId;
    }

    /// @notice Revoke a claim directly by providing claim data (for API mode).
    /// @dev Allows revocation using claim data instead of claimId lookup.
    ///      More convenient for off-chain systems that track claims by data.
    /// @param namespace The target namespace
    /// @param publicKey The agent's Ed25519 public key
    /// @param service The service identifier
    /// @return claimId The claim identifier that was revoked
    function revokeClaimDirect(
        string calldata namespace,
        bytes calldata publicKey,
        string calldata service
    ) external returns (bytes32) {
        if (msg.sender != namespaces[namespace].owner) revert NotNamespaceOwner();

        // Compute claim ID
        bytes32 claimId = keccak256(abi.encode(namespace, publicKey, service));
        Claim storage claim = claims[claimId];

        if (claim.status != ClaimStatus.Approved) revert ClaimNotApproved();

        claim.status = ClaimStatus.Revoked;
        claim.resolvedAt = block.timestamp;

        // Clear O(1) authorization lookup
        bytes32 authKey = keccak256(abi.encode(namespace, publicKey, service));
        _approvedClaims[authKey] = false;

        emit ClaimRevoked(claimId, namespace, service);
        return claimId;
    }

    // ─── Maintenance ─────────────────────────────────────────────────────────

    /// @notice Clean up expired pending claims for a namespace, freeing pendingClaimCount slots.
    /// @param namespace The namespace to clean
    /// @param maxIterations Maximum number of claims to iterate over (0 = no limit)
    /// @return cleaned The number of expired claims cleaned
    function cleanExpiredClaims(string calldata namespace, uint256 maxIterations) external returns (uint256 cleaned) {
        bytes32[] storage claimIds = namespaceClaims[namespace];
        uint256 len = claimIds.length;
        uint256 limit = maxIterations == 0 ? len : (maxIterations < len ? maxIterations : len);
        for (uint256 i = 0; i < limit; i++) {
            Claim storage claim = claims[claimIds[i]];
            if (
                claim.status == ClaimStatus.Pending
                    && block.timestamp - claim.createdAt > CLAIM_EXPIRY
            ) {
                claim.status = ClaimStatus.Expired;
                claim.resolvedAt = block.timestamp;
                pendingClaimCount[namespace]--;
                cleaned++;
            }
        }
        if (cleaned > 0) {
            emit ExpiredClaimsCleaned(namespace, cleaned);
        }
    }

    // ─── View Functions ──────────────────────────────────────────────────────

    /// @notice Check if a public key has an approved claim for a service under a namespace.
    /// @param namespace The namespace to check
    /// @param publicKey The agent's public key
    /// @param service The service to check
    /// @return authorized Whether the agent is authorized
    function isAuthorized(
        string calldata namespace,
        bytes calldata publicKey,
        string calldata service
    ) external view returns (bool) {
        bytes32 authKey = keccak256(abi.encode(namespace, publicKey, service));
        return _approvedClaims[authKey];
    }

    /// @notice Get all claim IDs for a namespace.
    /// @param namespace The namespace to query
    /// @return The array of claim IDs
    function getNamespaceClaims(string calldata namespace)
        external
        view
        returns (bytes32[] memory)
    {
        return namespaceClaims[namespace];
    }

    /// @notice Get claim details.
    /// @param claimId The claim ID to query
    /// @return The claim data
    function getClaim(bytes32 claimId) external view returns (Claim memory) {
        return claims[claimId];
    }
}
