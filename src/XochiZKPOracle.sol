// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IXochiZKPOracle} from "./interfaces/IXochiZKPOracle.sol";
import {IXochiZKPVerifier} from "./interfaces/IXochiZKPVerifier.sol";
import {IUltraVerifier} from "./interfaces/IUltraVerifier.sol";
import {ProofTypes} from "./libraries/ProofTypes.sol";
import {JurisdictionConfig} from "./libraries/JurisdictionConfig.sol";
import {Ownable2Step} from "./libraries/Ownable2Step.sol";
import {Pausable} from "./libraries/Pausable.sol";

/// @title XochiZKPOracle -- Reference implementation of the Xochi ZKP compliance oracle
/// @notice Records compliance attestations backed by verified ZK proofs and supports
///         retroactive proof-of-innocence lookups
contract XochiZKPOracle is IXochiZKPOracle, Ownable2Step, Pausable {
    /// @notice The verifier contract used to validate proofs
    IXochiZKPVerifier public immutable verifier;

    /// @notice Hash of the current provider weight configuration
    bytes32 internal _providerConfigHash;

    /// @notice Duration in seconds that attestations remain valid (default: 24 hours)
    uint256 internal _attestationTTL;

    /// @notice Latest attestation per subject per jurisdiction
    /// @dev subject => jurisdictionId => attestation
    mapping(address subject => mapping(uint8 jurisdictionId => ComplianceAttestation attestation)) internal
        _attestations;

    /// @notice Attestation lookup by proof hash (for retroactive verification)
    mapping(bytes32 proofHash => ComplianceAttestation attestation) internal _proofIndex;

    /// @notice History of proof hashes per subject per jurisdiction
    /// @dev subject => jurisdictionId => proofHash[]
    mapping(address subject => mapping(uint8 jurisdictionId => bytes32[] proofHashes)) internal _attestationHistory;

    /// @notice Historical provider config hashes (versioned)
    bytes32[] internal _configHistory;

    /// @notice Track used proof hashes to prevent replay
    mapping(bytes32 proofHash => bool used) internal _usedProofs;

    /// @notice Proof type per proof hash (for downstream proof-type verification)
    mapping(bytes32 proofHash => uint8 proofType) internal _proofTypes;

    /// @notice Set of all valid (current + historical) provider config hashes
    mapping(bytes32 configHash => bool valid) internal _validConfigs;

    /// @notice Set of valid merkle roots for MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION proofs
    mapping(bytes32 merkleRoot => bool valid) internal _validMerkleRoots;

    /// @notice Registered reporting thresholds for PATTERN proofs (anti-structuring)
    /// @dev Maps threshold value (as bytes32) to validity. Prevents jurisdiction spoofing
    ///      by ensuring the reporting_threshold in a PATTERN proof matches a registered value.
    mapping(bytes32 threshold => bool valid) internal _validReportingThresholds;

    /// @notice Per-proof-type pause state for surgical incident response
    mapping(uint8 proofType => bool isPaused) internal _proofTypePaused;

    error ProofVerificationFailed();
    error ProofAlreadyUsed(bytes32 proofHash);
    error InvalidTTL();
    error AttestationNotFound(bytes32 proofHash);
    error PublicInputMismatch();
    error InvalidConfigHash(bytes32 configHash);
    error InvalidMerkleRoot(bytes32 merkleRoot);
    error InvalidReportingThreshold(bytes32 threshold);
    error CannotRevokeCurrentConfig();
    error ProofResultNegative();
    error SubmitterMismatch();
    error ConfigHistoryFull();
    error ConfigAlreadyCurrent();
    error AlreadyRegistered();
    error NotRegistered();
    error BatchLengthMismatch();
    error EmptyBatch();
    error BatchTooLarge();
    error TimeWindowTooSmall(uint256 timeWindow, uint256 minimum);
    error ProofTimestampStale(uint256 proofTimestamp, uint256 blockTimestamp);
    error ProofTypePaused(uint8 proofType);
    error ProofTypeNotPaused(uint8 proofType);

    /// @notice Maximum number of entries in the config history array
    uint256 public constant MAX_CONFIG_HISTORY = 256;

    /// @notice Maximum number of proofs in a single batch submission
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Minimum time window for PATTERN (anti-structuring) proofs in seconds
    uint256 public constant MIN_TIME_WINDOW = 3600;

    /// @notice Maximum age of a proof timestamp relative to block.timestamp
    uint256 public constant MAX_PROOF_AGE = 1 hours;

    /// @param _verifier The XochiZKPVerifier contract address
    /// @param initialOwner The initial owner address
    /// @param initialConfigHash The initial provider weight configuration hash
    constructor(address _verifier, address initialOwner, bytes32 initialConfigHash) {
        if (_verifier == address(0) || initialOwner == address(0)) revert ZeroAddress();
        if (initialConfigHash == bytes32(0)) revert InvalidConfigHash(bytes32(0));

        verifier = IXochiZKPVerifier(_verifier);
        owner = initialOwner;
        _providerConfigHash = initialConfigHash;
        _attestationTTL = 24 hours;

        _configHistory.push(initialConfigHash);
        _validConfigs[initialConfigHash] = true;

        emit OwnershipTransferred(address(0), initialOwner);
        emit ProviderWeightsUpdated(initialConfigHash, block.timestamp, "");
    }

    // -------------------------------------------------------------------------
    // IXochiZKPOracle -- Core
    // -------------------------------------------------------------------------

    /// @inheritdoc IXochiZKPOracle
    function submitCompliance(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 providerSetHash
    ) external whenNotPaused returns (ComplianceAttestation memory attestation) {
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        JurisdictionConfig.validateJurisdiction(jurisdictionId);

        // Validate that caller-supplied parameters match what's in the proof's public inputs.
        // This prevents submitting a proof generated for one context in a different context.
        if (proofType == ProofTypes.COMPLIANCE) {
            _validateComplianceInputs(jurisdictionId, providerSetHash, publicInputs);
        } else if (proofType == ProofTypes.RISK_SCORE) {
            _validateRiskScoreInputs(publicInputs);
        } else if (proofType == ProofTypes.PATTERN) {
            _validatePatternInputs(publicInputs);
        } else if (proofType == ProofTypes.ATTESTATION) {
            _validateAttestationInputs(publicInputs);
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            _validateMembershipInputs(publicInputs);
        } else if (proofType == ProofTypes.NON_MEMBERSHIP) {
            _validateNonMembershipInputs(publicInputs);
        } else {
            revert ProofTypes.InvalidProofType(proofType);
        }

        // Verify proof and check replay (extracted to reduce stack depth)
        (address verifierUsed, bytes32 proofHash) = _verifyAndRecordProof(proofType, proof, publicInputs);

        // Build and store attestation (providerSetHash only meaningful for COMPLIANCE proofs)
        bytes32 effectiveProviderSetHash = proofType == ProofTypes.COMPLIANCE ? providerSetHash : bytes32(0);
        attestation = _buildAttestation(
            jurisdictionId, proofType, proofHash, effectiveProviderSetHash, keccak256(publicInputs), verifierUsed
        );

        uint256 previousExpiresAt = _attestations[msg.sender][jurisdictionId].expiresAt;
        _attestations[msg.sender][jurisdictionId] = attestation;
        _proofIndex[proofHash] = attestation;
        _proofTypes[proofHash] = proofType;
        _attestationHistory[msg.sender][jurisdictionId].push(proofHash);

        emit ComplianceVerified(msg.sender, jurisdictionId, true, proofHash, attestation.expiresAt, previousExpiresAt);
    }

    /// @inheritdoc IXochiZKPOracle
    function submitComplianceBatch(
        uint8 jurisdictionId,
        uint8[] calldata proofTypes,
        bytes[] calldata proofs,
        bytes[] calldata publicInputs,
        bytes32[] calldata providerSetHashes
    ) external whenNotPaused returns (ComplianceAttestation[] memory attestations) {
        uint256 length = proofTypes.length;
        if (length == 0) revert EmptyBatch();
        if (length > MAX_BATCH_SIZE) revert BatchTooLarge();
        if (length != proofs.length || length != publicInputs.length || length != providerSetHashes.length) {
            revert BatchLengthMismatch();
        }

        JurisdictionConfig.validateJurisdiction(jurisdictionId);

        attestations = new ComplianceAttestation[](length);

        for (uint256 i; i < length;) {
            attestations[i] =
                _submitSingle(jurisdictionId, proofTypes[i], proofs[i], publicInputs[i], providerSetHashes[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IXochiZKPOracle
    function checkCompliance(address subject, uint8 jurisdictionId)
        external
        view
        returns (bool valid, ComplianceAttestation memory attestation)
    {
        attestation = _attestations[subject][jurisdictionId];

        // Valid if attestation exists, threshold was met, and not expired
        valid = attestation.timestamp > 0 && attestation.meetsThreshold && block.timestamp <= attestation.expiresAt;
    }

    /// @inheritdoc IXochiZKPOracle
    function checkComplianceByType(address subject, uint8 jurisdictionId, uint8 proofType)
        external
        view
        returns (bool valid, ComplianceAttestation memory attestation)
    {
        attestation = _attestations[subject][jurisdictionId];
        valid = attestation.timestamp > 0 && attestation.meetsThreshold && block.timestamp <= attestation.expiresAt
            && attestation.proofType == proofType;
    }

    /// @inheritdoc IXochiZKPOracle
    function getHistoricalProof(bytes32 proofHash) external view returns (ComplianceAttestation memory attestation) {
        attestation = _proofIndex[proofHash];
        if (attestation.timestamp == 0) revert AttestationNotFound(proofHash);
    }

    /// @inheritdoc IXochiZKPOracle
    function getProofType(bytes32 proofHash) external view returns (uint8) {
        if (_proofIndex[proofHash].timestamp == 0) revert AttestationNotFound(proofHash);
        return _proofTypes[proofHash];
    }

    /// @inheritdoc IXochiZKPOracle
    /// @dev Returns the entire history array. For subjects with many attestations this
    ///      may exceed RPC response limits. Prefer getAttestationHistoryPaginated() for
    ///      production use.
    function getAttestationHistory(address subject, uint8 jurisdictionId)
        external
        view
        returns (bytes32[] memory proofHashes)
    {
        return _attestationHistory[subject][jurisdictionId];
    }

    /// @notice Get a paginated slice of attestation history
    /// @param subject The address to query
    /// @param jurisdictionId The jurisdiction
    /// @param offset Starting index
    /// @param limit Maximum number of entries to return
    /// @return proofHashes The proof hashes in the requested range
    /// @return total Total number of attestations for pagination
    function getAttestationHistoryPaginated(address subject, uint8 jurisdictionId, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory proofHashes, uint256 total)
    {
        bytes32[] storage history = _attestationHistory[subject][jurisdictionId];
        total = history.length;

        if (offset >= total) {
            return (new bytes32[](0), total);
        }

        uint256 end = offset + limit;
        if (end > total) end = total;
        uint256 count = end - offset;

        proofHashes = new bytes32[](count);
        for (uint256 i; i < count;) {
            proofHashes[i] = history[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IXochiZKPOracle
    function providerConfigHash() external view returns (bytes32 configHash) {
        return _providerConfigHash;
    }

    /// @inheritdoc IXochiZKPOracle
    function attestationTTL() external view returns (uint256 ttl) {
        return _attestationTTL;
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    /// @notice Update the provider weight configuration
    /// @param newConfigHash The new configuration hash
    /// @param metadataURI URI pointing to the full config (IPFS, Arweave, etc.)
    function updateProviderConfig(bytes32 newConfigHash, string calldata metadataURI) external onlyOwner {
        if (newConfigHash == _providerConfigHash) revert ConfigAlreadyCurrent();
        if (_configHistory.length >= MAX_CONFIG_HISTORY) revert ConfigHistoryFull();
        _providerConfigHash = newConfigHash;
        _configHistory.push(newConfigHash);
        _validConfigs[newConfigHash] = true;
        emit ProviderWeightsUpdated(newConfigHash, block.timestamp, metadataURI);
    }

    /// @notice Update the attestation TTL
    /// @param newTTL The new TTL in seconds (minimum 1 hour, maximum 30 days)
    function updateAttestationTTL(uint256 newTTL) external onlyOwner {
        if (newTTL < 1 hours || newTTL > 30 days) revert InvalidTTL();
        uint256 oldTTL = _attestationTTL;
        _attestationTTL = newTTL;
        emit AttestationTTLUpdated(oldTTL, newTTL);
    }

    /// @notice Get the number of historical provider config versions
    /// @return count Number of config versions
    function configHistoryLength() external view returns (uint256 count) {
        return _configHistory.length;
    }

    /// @notice Get a historical provider config hash by index
    /// @param index The version index (0 = initial)
    /// @return configHash The config hash at that version
    function configHistoryAt(uint256 index) external view returns (bytes32 configHash) {
        return _configHistory[index];
    }

    /// @notice Revoke a provider config hash so proofs using it are no longer accepted
    /// @param configHash The config hash to revoke (cannot be the current active config)
    function revokeConfig(bytes32 configHash) external onlyOwner {
        if (configHash == _providerConfigHash) revert CannotRevokeCurrentConfig();
        _validConfigs[configHash] = false;
        emit ConfigRevoked(configHash);
    }

    /// @notice Check if a config hash is valid (current or historical, not revoked)
    /// @param configHash The config hash to check
    /// @return valid Whether the config hash has been registered and not revoked
    function isValidConfig(bytes32 configHash) external view returns (bool valid) {
        return _validConfigs[configHash];
    }

    /// @notice Register a merkle root as valid for MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION proofs
    /// @param merkleRoot The merkle root to register
    function registerMerkleRoot(bytes32 merkleRoot) external onlyOwner {
        if (_validMerkleRoots[merkleRoot]) revert AlreadyRegistered();
        _validMerkleRoots[merkleRoot] = true;
        emit MerkleRootRegistered(merkleRoot);
    }

    /// @notice Revoke a merkle root so proofs using it are no longer accepted
    /// @param merkleRoot The merkle root to revoke
    function revokeMerkleRoot(bytes32 merkleRoot) external onlyOwner {
        if (!_validMerkleRoots[merkleRoot]) revert NotRegistered();
        _validMerkleRoots[merkleRoot] = false;
        emit MerkleRootRevoked(merkleRoot);
    }

    /// @notice Check if a merkle root is valid
    /// @param merkleRoot The merkle root to check
    /// @return valid Whether the merkle root has been registered and not revoked
    function isValidMerkleRoot(bytes32 merkleRoot) external view returns (bool valid) {
        return _validMerkleRoots[merkleRoot];
    }

    /// @notice Register a reporting threshold for PATTERN (anti-structuring) proofs
    /// @param threshold The threshold value (as bytes32-encoded u64)
    function registerReportingThreshold(bytes32 threshold) external onlyOwner {
        if (_validReportingThresholds[threshold]) revert AlreadyRegistered();
        _validReportingThresholds[threshold] = true;
        emit ReportingThresholdRegistered(threshold);
    }

    /// @notice Revoke a reporting threshold
    /// @param threshold The threshold to revoke
    function revokeReportingThreshold(bytes32 threshold) external onlyOwner {
        if (!_validReportingThresholds[threshold]) revert NotRegistered();
        _validReportingThresholds[threshold] = false;
        emit ReportingThresholdRevoked(threshold);
    }

    /// @notice Check if a reporting threshold is valid
    /// @param threshold The threshold to check
    /// @return valid Whether the threshold has been registered and not revoked
    function isValidReportingThreshold(bytes32 threshold) external view returns (bool valid) {
        return _validReportingThresholds[threshold];
    }

    /// @notice Pause the contract, blocking all new submissions
    function pause() external override onlyOwner {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause the contract, resuming all submissions
    function unpause() external override onlyOwner {
        if (!paused) revert ContractNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Pause submissions for a single proof type (surgical response)
    /// @param proofType The proof type to pause (0x01-0x06)
    function pauseProofType(uint8 proofType) external onlyOwner {
        if (!ProofTypes.isValidProofType(proofType)) revert ProofTypes.InvalidProofType(proofType);
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        _proofTypePaused[proofType] = true;
        emit ProofTypePausedEvent(proofType, msg.sender);
    }

    /// @notice Unpause submissions for a single proof type
    /// @param proofType The proof type to unpause (0x01-0x06)
    function unpauseProofType(uint8 proofType) external onlyOwner {
        if (!ProofTypes.isValidProofType(proofType)) revert ProofTypes.InvalidProofType(proofType);
        if (!_proofTypePaused[proofType]) revert ProofTypeNotPaused(proofType);
        _proofTypePaused[proofType] = false;
        emit ProofTypeUnpausedEvent(proofType, msg.sender);
    }

    /// @notice Check if a specific proof type is paused
    /// @param proofType The proof type to check
    /// @return Whether the proof type is paused
    function isProofTypePaused(uint8 proofType) external view returns (bool) {
        return _proofTypePaused[proofType];
    }

    event ProofTypePausedEvent(uint8 indexed proofType, address indexed account);
    event ProofTypeUnpausedEvent(uint8 indexed proofType, address indexed account);

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Process a single entry in a batch (or standalone) submission.
    ///      Extracted to avoid stack-too-deep in the batch loop.
    function _submitSingle(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes calldata proof,
        bytes calldata inputs,
        bytes32 providerSetHash
    ) internal returns (ComplianceAttestation memory attestation) {
        if (_proofTypePaused[proofType]) revert ProofTypePaused(proofType);
        if (proofType == ProofTypes.COMPLIANCE) {
            _validateComplianceInputs(jurisdictionId, providerSetHash, inputs);
        } else if (proofType == ProofTypes.RISK_SCORE) {
            _validateRiskScoreInputs(inputs);
        } else if (proofType == ProofTypes.PATTERN) {
            _validatePatternInputs(inputs);
        } else if (proofType == ProofTypes.ATTESTATION) {
            _validateAttestationInputs(inputs);
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            _validateMembershipInputs(inputs);
        } else if (proofType == ProofTypes.NON_MEMBERSHIP) {
            _validateNonMembershipInputs(inputs);
        } else {
            revert ProofTypes.InvalidProofType(proofType);
        }

        (address verifierUsed, bytes32 proofHash) = _verifyAndRecordProof(proofType, proof, inputs);

        bytes32 effectiveProviderSetHash = proofType == ProofTypes.COMPLIANCE ? providerSetHash : bytes32(0);
        attestation = _buildAttestation(
            jurisdictionId, proofType, proofHash, effectiveProviderSetHash, keccak256(inputs), verifierUsed
        );

        uint256 previousExpiresAt = _attestations[msg.sender][jurisdictionId].expiresAt;
        _attestations[msg.sender][jurisdictionId] = attestation;
        _proofIndex[proofHash] = attestation;
        _proofTypes[proofHash] = proofType;
        _attestationHistory[msg.sender][jurisdictionId].push(proofHash);

        emit ComplianceVerified(msg.sender, jurisdictionId, true, proofHash, attestation.expiresAt, previousExpiresAt);
    }

    /// @dev Verify the ZK proof and record replay protection.
    ///      Resolves verifier address once to eliminate TOCTOU.
    function _verifyAndRecordProof(uint8 proofType, bytes calldata proof, bytes calldata publicInputs)
        internal
        returns (address verifierUsed, bytes32 proofHash)
    {
        verifierUsed = verifier.getVerifier(proofType);
        if (verifierUsed == address(0)) revert ProofVerificationFailed();
        ProofTypes.validatePublicInputs(proofType, publicInputs);
        bytes32[] memory inputs = ProofTypes.decodePublicInputs(publicInputs);
        bool valid = IUltraVerifier(verifierUsed).verify(proof, inputs);
        if (!valid) revert ProofVerificationFailed();

        // Key on (proof, proofType) so identical proof bytes for different types don't collide
        proofHash = keccak256(abi.encodePacked(proof, proofType));
        if (_usedProofs[proofHash]) revert ProofAlreadyUsed(proofHash);
        _usedProofs[proofHash] = true;
    }

    /// @dev Build a ComplianceAttestation struct (extracted to reduce stack depth)
    function _buildAttestation(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes32 proofHash,
        bytes32 providerSetHash,
        bytes32 publicInputsHash,
        address verifierUsed
    ) internal view returns (ComplianceAttestation memory attestation) {
        attestation = ComplianceAttestation({
            subject: msg.sender,
            jurisdictionId: jurisdictionId,
            proofType: proofType,
            meetsThreshold: true,
            timestamp: block.timestamp,
            expiresAt: block.timestamp + _attestationTTL,
            proofHash: proofHash,
            providerSetHash: providerSetHash,
            publicInputsHash: publicInputsHash,
            verifierUsed: verifierUsed
        });
    }

    /// @dev Check that a proof timestamp is within MAX_PROOF_AGE of block.timestamp
    function _validateProofTimestamp(uint256 proofTimestamp) internal view {
        uint256 diff =
            block.timestamp > proofTimestamp ? block.timestamp - proofTimestamp : proofTimestamp - block.timestamp;
        if (diff > MAX_PROOF_AGE) revert ProofTimestampStale(proofTimestamp, block.timestamp);
    }

    /// @dev Validate that caller-supplied jurisdiction and providerSetHash match
    ///      the corresponding fields in the COMPLIANCE proof's public inputs,
    ///      and that the config_hash is a known (current or historical) config.
    function _validateComplianceInputs(uint8 jurisdictionId, bytes32 providerSetHash, bytes calldata publicInputs)
        internal
        view
    {
        // COMPLIANCE public inputs layout (each 32 bytes):
        //   [0]: jurisdiction_id
        //   [1]: provider_set_hash
        //   [2]: config_hash
        //   [3]: timestamp
        //   [4]: meets_threshold
        //   [5]: submitter
        bytes32 proofJurisdiction = bytes32(publicInputs[0:32]);
        bytes32 proofProviderSet = bytes32(publicInputs[32:64]);
        bytes32 proofConfigHash = bytes32(publicInputs[64:96]);
        bytes32 proofMeetsThreshold = bytes32(publicInputs[128:160]);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));

        if (proofJurisdiction != bytes32(uint256(jurisdictionId))) revert PublicInputMismatch();
        if (proofProviderSet != providerSetHash) revert PublicInputMismatch();
        if (!_validConfigs[proofConfigHash]) revert InvalidConfigHash(proofConfigHash);
        if (proofMeetsThreshold != bytes32(uint256(1))) revert ProofResultNegative();
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
        uint256 proofTimestamp = uint256(bytes32(publicInputs[96:128]));
        _validateProofTimestamp(proofTimestamp);
    }

    /// @dev Validate that the config_hash in RISK_SCORE public inputs is a known config
    ///      and that the result field indicates a positive outcome.
    ///      NOTE: RISK_SCORE has no timestamp in public inputs; staleness not enforced.
    function _validateRiskScoreInputs(bytes calldata publicInputs) internal view {
        // RISK_SCORE public inputs layout (each 32 bytes):
        //   [0]: proof_type
        //   [1]: direction
        //   [2]: bound_lower
        //   [3]: bound_upper
        //   [4]: result
        //   [5]: config_hash
        //   [6]: provider_set_hash
        //   [7]: submitter
        bytes32 proofResult = bytes32(publicInputs[128:160]);
        bytes32 proofConfigHash = bytes32(publicInputs[160:192]);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[224:256]))));
        if (proofResult != bytes32(uint256(1))) revert ProofResultNegative();
        if (!_validConfigs[proofConfigHash]) revert InvalidConfigHash(proofConfigHash);
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate PATTERN public inputs.
    ///      Ensures result is positive, reporting_threshold is registered, tx_set_hash is non-zero,
    ///      time_window meets minimum, and submitter matches msg.sender.
    ///      NOTE: PATTERN uses time_window (not a timestamp); staleness not enforced.
    function _validatePatternInputs(bytes calldata publicInputs) internal view {
        // PATTERN public inputs layout (each 32 bytes):
        //   [0]: analysis_type
        //   [1]: result
        //   [2]: reporting_threshold
        //   [3]: time_window
        //   [4]: tx_set_hash
        //   [5]: submitter
        bytes32 proofResult = bytes32(publicInputs[32:64]);
        if (proofResult != bytes32(uint256(1))) revert ProofResultNegative();
        bytes32 reportingThreshold = bytes32(publicInputs[64:96]);
        if (!_validReportingThresholds[reportingThreshold]) {
            revert InvalidReportingThreshold(reportingThreshold);
        }
        uint256 timeWindow = uint256(bytes32(publicInputs[96:128]));
        if (timeWindow < MIN_TIME_WINDOW) revert TimeWindowTooSmall(timeWindow, MIN_TIME_WINDOW);
        bytes32 txSetHash = bytes32(publicInputs[128:160]);
        if (txSetHash == bytes32(0)) revert PublicInputMismatch();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate ATTESTATION public inputs.
    ///      Ensures is_valid is true, merkle_root is registered, and submitter matches msg.sender.
    function _validateAttestationInputs(bytes calldata publicInputs) internal view {
        // ATTESTATION public inputs layout (each 32 bytes):
        //   [0]: provider_id
        //   [1]: credential_type
        //   [2]: is_valid
        //   [3]: merkle_root
        //   [4]: current_timestamp
        //   [5]: submitter
        bytes32 proofIsValid = bytes32(publicInputs[64:96]);
        if (proofIsValid != bytes32(uint256(1))) revert ProofResultNegative();
        bytes32 merkleRoot = bytes32(publicInputs[96:128]);
        if (!_validMerkleRoots[merkleRoot]) revert InvalidMerkleRoot(merkleRoot);
        uint256 proofTimestamp = uint256(bytes32(publicInputs[128:160]));
        _validateProofTimestamp(proofTimestamp);
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[160:192]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate MEMBERSHIP public inputs.
    ///      Ensures is_member is true, merkle_root is registered, and submitter matches msg.sender.
    function _validateMembershipInputs(bytes calldata publicInputs) internal view {
        // MEMBERSHIP public inputs layout (each 32 bytes):
        //   [0]: merkle_root
        //   [1]: set_id
        //   [2]: timestamp
        //   [3]: is_member
        //   [4]: submitter
        bytes32 merkleRoot = bytes32(publicInputs[0:32]);
        if (!_validMerkleRoots[merkleRoot]) revert InvalidMerkleRoot(merkleRoot);
        uint256 proofTimestamp = uint256(bytes32(publicInputs[64:96]));
        _validateProofTimestamp(proofTimestamp);
        bytes32 proofIsMember = bytes32(publicInputs[96:128]);
        if (proofIsMember != bytes32(uint256(1))) revert ProofResultNegative();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[128:160]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }

    /// @dev Validate NON_MEMBERSHIP public inputs.
    ///      Ensures is_non_member is true, merkle_root is registered, and submitter matches msg.sender.
    function _validateNonMembershipInputs(bytes calldata publicInputs) internal view {
        // NON_MEMBERSHIP public inputs layout (each 32 bytes):
        //   [0]: merkle_root
        //   [1]: set_id
        //   [2]: timestamp
        //   [3]: is_non_member
        //   [4]: submitter
        bytes32 merkleRoot = bytes32(publicInputs[0:32]);
        if (!_validMerkleRoots[merkleRoot]) revert InvalidMerkleRoot(merkleRoot);
        uint256 proofTimestamp = uint256(bytes32(publicInputs[64:96]));
        _validateProofTimestamp(proofTimestamp);
        bytes32 proofIsNonMember = bytes32(publicInputs[96:128]);
        if (proofIsNonMember != bytes32(uint256(1))) revert ProofResultNegative();
        address proofSubmitter = address(uint160(uint256(bytes32(publicInputs[128:160]))));
        if (proofSubmitter != msg.sender) revert SubmitterMismatch();
    }
}
