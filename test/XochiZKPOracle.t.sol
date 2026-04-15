// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IXochiZKPOracle} from "../src/interfaces/IXochiZKPOracle.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {JurisdictionConfig} from "../src/libraries/JurisdictionConfig.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {Pausable} from "../src/libraries/Pausable.sol";

contract AlwaysPassVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract XochiZKPOracleTest is Test {
    XochiZKPOracle internal oracle;
    XochiZKPVerifier internal verifier;
    AlwaysPassVerifier internal stubVerifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    bytes32 internal constant INITIAL_CONFIG = keccak256("initial-config");

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        oracle = new XochiZKPOracle(address(verifier), owner, INITIAL_CONFIG);

        stubVerifier = new AlwaysPassVerifier();
        vm.startPrank(owner);
        for (uint8 i = ProofTypes.COMPLIANCE; i <= ProofTypes.NON_MEMBERSHIP; i++) {
            verifier.setVerifier(i, address(stubVerifier));
        }
        // Register default reporting threshold for PATTERN tests
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_constructor_setsState() public view {
        assertEq(address(oracle.verifier()), address(verifier));
        assertEq(oracle.owner(), owner);
        assertEq(oracle.providerConfigHash(), INITIAL_CONFIG);
        assertEq(oracle.attestationTTL(), 24 hours);
    }

    function test_constructor_revert_zeroVerifier() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPOracle(address(0), owner, INITIAL_CONFIG);
    }

    function test_constructor_revert_zeroOwner() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPOracle(address(verifier), address(0), INITIAL_CONFIG);
    }

    // -------------------------------------------------------------------------
    // submitCompliance
    // -------------------------------------------------------------------------

    function test_submitCompliance_recordsAttestation() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, 0);
        assertTrue(att.meetsThreshold);
        assertEq(att.timestamp, block.timestamp);
        assertEq(att.expiresAt, block.timestamp + 24 hours);
        assertEq(att.proofHash, keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE)));
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_emitsEvent() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IXochiZKPOracle.ComplianceVerified(
            alice, 0, true, keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE)), block.timestamp + 24 hours, 0
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_emitsEvent_withPreviousExpiry() public {
        // First submission
        _submitForAlice(0);
        uint256 firstExpiresAt = block.timestamp + 24 hours;

        // Second submission should emit the first expiry
        bytes memory proof2 = _uniqueProof();
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IXochiZKPOracle.ComplianceVerified(
            alice,
            0,
            true,
            keccak256(abi.encodePacked(proof2, ProofTypes.COMPLIANCE)),
            block.timestamp + 24 hours,
            firstExpiresAt
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_invalidJurisdiction() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(JurisdictionConfig.InvalidJurisdiction.selector, 4));
        oracle.submitCompliance(
            4,
            ProofTypes.COMPLIANCE,
            _uniqueProof(),
            _complianceInputsFor(4, DEFAULT_PROVIDER_SET_HASH),
            DEFAULT_PROVIDER_SET_HASH
        );
    }

    // -------------------------------------------------------------------------
    // checkCompliance
    // -------------------------------------------------------------------------

    function test_checkCompliance_validAttestation() public {
        _submitForAlice(0);

        (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) = oracle.checkCompliance(alice, 0);

        assertTrue(valid);
        assertEq(att.subject, alice);
    }

    function test_checkCompliance_expired() public {
        _submitForAlice(0);
        vm.warp(block.timestamp + 24 hours + 1);

        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function test_checkCompliance_noAttestation() public view {
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function test_checkCompliance_wrongJurisdiction() public {
        _submitForAlice(0); // EU

        (bool valid,) = oracle.checkCompliance(alice, 1); // US
        assertFalse(valid);
    }

    // -------------------------------------------------------------------------
    // getHistoricalProof
    // -------------------------------------------------------------------------

    function test_getHistoricalProof_returnsAttestation() public {
        bytes memory proof = _uniqueProof();

        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        bytes32 proofHash = keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE));
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);

        assertEq(att.subject, alice);
        assertEq(att.proofHash, proofHash);
    }

    function test_getHistoricalProof_revert_notFound() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.AttestationNotFound.selector, bytes32(uint256(999))));
        oracle.getHistoricalProof(bytes32(uint256(999)));
    }

    // -------------------------------------------------------------------------
    // getAttestationHistory
    // -------------------------------------------------------------------------

    function test_getAttestationHistory_tracksMultiple() public {
        bytes memory proof1 = _uniqueProof();
        bytes memory proof2 = _uniqueProof();

        vm.startPrank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        vm.stopPrank();

        bytes32[] memory history = oracle.getAttestationHistory(alice, 0);
        assertEq(history.length, 2);
        assertEq(history[0], keccak256(abi.encodePacked(proof1, ProofTypes.COMPLIANCE)));
        assertEq(history[1], keccak256(abi.encodePacked(proof2, ProofTypes.COMPLIANCE)));
    }

    // -------------------------------------------------------------------------
    // Admin: provider config
    // -------------------------------------------------------------------------

    function test_updateProviderConfig() public {
        bytes32 newConfig = keccak256("new-config");
        string memory uri = "ipfs://QmNewConfig";

        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IXochiZKPOracle.ProviderWeightsUpdated(newConfig, block.timestamp, uri);
        oracle.updateProviderConfig(newConfig, uri);

        assertEq(oracle.providerConfigHash(), newConfig);
        assertEq(oracle.configHistoryLength(), 2);
        assertEq(oracle.configHistoryAt(1), newConfig);
    }

    function test_updateProviderConfig_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.updateProviderConfig(bytes32(0), "");
    }

    // -------------------------------------------------------------------------
    // Admin: attestation TTL
    // -------------------------------------------------------------------------

    function test_updateAttestationTTL() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit IXochiZKPOracle.AttestationTTLUpdated(24 hours, 12 hours);
        oracle.updateAttestationTTL(12 hours);

        assertEq(oracle.attestationTTL(), 12 hours);
    }

    function test_updateAttestationTTL_revert_tooLow() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(30 minutes);
    }

    function test_updateAttestationTTL_revert_tooHigh() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(31 days);
    }

    // -------------------------------------------------------------------------
    // Proof replay protection
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_proofReplay() public {
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputs();

        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                XochiZKPOracle.ProofAlreadyUsed.selector, keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE))
            )
        );
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Public input validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_jurisdictionMismatch() public {
        // Public inputs say jurisdiction=0 (EU), but caller passes jurisdiction=1 (US)
        bytes memory publicInputs = _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH);
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(1, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_providerSetHashMismatch() public {
        // Public inputs have providerSetHash=0xaabb, but caller passes different hash
        bytes memory publicInputs = _complianceInputs();
        bytes32 wrongHash = keccak256("wrong");
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, wrongHash);
    }

    // -------------------------------------------------------------------------
    // Paginated history
    // -------------------------------------------------------------------------

    function test_getAttestationHistoryPaginated() public {
        // Submit 5 proofs
        vm.startPrank(alice);
        bytes32[5] memory hashes;
        for (uint256 i; i < 5; i++) {
            bytes memory proof = _uniqueProof();
            hashes[i] = keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE));
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
        }
        vm.stopPrank();

        // Page 1: offset=0, limit=2
        (bytes32[] memory page1, uint256 total1) = oracle.getAttestationHistoryPaginated(alice, 0, 0, 2);
        assertEq(total1, 5);
        assertEq(page1.length, 2);
        assertEq(page1[0], hashes[0]);
        assertEq(page1[1], hashes[1]);

        // Page 2: offset=2, limit=2
        (bytes32[] memory page2,) = oracle.getAttestationHistoryPaginated(alice, 0, 2, 2);
        assertEq(page2.length, 2);
        assertEq(page2[0], hashes[2]);

        // Page 3: offset=4, limit=2 (only 1 remaining)
        (bytes32[] memory page3,) = oracle.getAttestationHistoryPaginated(alice, 0, 4, 2);
        assertEq(page3.length, 1);
        assertEq(page3[0], hashes[4]);

        // Beyond end
        (bytes32[] memory empty,) = oracle.getAttestationHistoryPaginated(alice, 0, 10, 2);
        assertEq(empty.length, 0);
    }

    // -------------------------------------------------------------------------
    // Concurrent attestations (same user, multiple jurisdictions)
    // -------------------------------------------------------------------------

    function test_concurrentAttestations_multipleJurisdictions() public {
        // Alice submits compliance for EU (0), US (1), UK (2)
        for (uint8 j; j < 3; j++) {
            _submitForAlice(j);
        }

        // Each jurisdiction has independent valid attestation
        for (uint8 j; j < 3; j++) {
            (bool valid, IXochiZKPOracle.ComplianceAttestation memory att) = oracle.checkCompliance(alice, j);
            assertTrue(valid);
            assertEq(att.jurisdictionId, j);
            assertEq(att.subject, alice);
        }

        // Singapore (3) has no attestation
        (bool valid3,) = oracle.checkCompliance(alice, 3);
        assertFalse(valid3);
    }

    function test_concurrentAttestations_independentExpiry() public {
        _submitForAlice(0); // EU
        vm.warp(block.timestamp + 12 hours);
        _submitForAlice(1); // US (submitted 12h later)

        // Fast forward to EU expiry but before US expiry
        vm.warp(block.timestamp + 12 hours + 1);

        (bool euValid,) = oracle.checkCompliance(alice, 0);
        (bool usValid,) = oracle.checkCompliance(alice, 1);
        assertFalse(euValid); // expired
        assertTrue(usValid); // still valid
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    function test_transferOwnership_twoStep() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        vm.prank(alice);
        oracle.acceptOwnership();

        assertEq(oracle.owner(), alice);
    }

    function test_transferOwnership_revert_expired() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(alice);
        vm.expectRevert(Ownable2Step.OwnershipTransferExpired.selector);
        oracle.acceptOwnership();
    }

    function test_transferOwnership_resetClearsPending() public {
        vm.prank(owner);
        oracle.transferOwnership(alice);

        // Owner can re-initiate, overwriting alice
        address bob = makeAddr("bob");
        vm.prank(owner);
        oracle.transferOwnership(bob);

        // Alice can no longer accept
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.NotPendingOwner.selector);
        oracle.acceptOwnership();

        // Bob can accept
        vm.prank(bob);
        oracle.acceptOwnership();
        assertEq(oracle.owner(), bob);
    }

    // -------------------------------------------------------------------------
    // Non-compliance proof types bypass input validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_riskScore_validConfigHash() public {
        bytes memory publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    // -------------------------------------------------------------------------
    // F2: providerSetHash zeroed for non-COMPLIANCE proofs
    // -------------------------------------------------------------------------

    function test_submitCompliance_nonComplianceProof_zerosProviderSetHash() public {
        bytes memory publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        bytes32 arbitraryHash = keccak256("arbitrary");
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, arbitraryHash);
        assertEq(att.providerSetHash, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Verifier used tracking
    // -------------------------------------------------------------------------

    function test_submitCompliance_capturesVerifierUsed() public {
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        assertEq(att.verifierUsed, address(stubVerifier));
    }

    function test_submitCompliance_verifierUsedSurvivesUpgrade() public {
        // Submit with original verifier
        bytes memory proof1 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att1 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Upgrade verifier
        AlwaysPassVerifier newStub = new AlwaysPassVerifier();
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(newStub));

        // Submit with new verifier
        bytes memory proof2 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att2 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Historical proof preserves original verifier
        IXochiZKPOracle.ComplianceAttestation memory historical =
            oracle.getHistoricalProof(keccak256(abi.encodePacked(proof1, ProofTypes.COMPLIANCE)));
        assertEq(historical.verifierUsed, address(stubVerifier));
        assertEq(att1.verifierUsed, address(stubVerifier));
        assertEq(att2.verifierUsed, address(newStub));
    }

    // -------------------------------------------------------------------------
    // Config hash validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_invalidConfigHash() public {
        // Build compliance inputs with an unregistered config hash
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH, // provider_set_hash
            bytes32(uint256(0xdead)), // config_hash (not registered)
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // meets_threshold
        );
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_riskScore_invalidConfigHash() public {
        bytes32 badConfig = bytes32(uint256(0xdead));
        bytes memory publicInputs = _riskScoreInputs(badConfig);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, badConfig));
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_historicalConfigHashAccepted() public {
        // Update config so INITIAL_CONFIG becomes historical (not current)
        bytes32 newConfig = keccak256("new-config");
        vm.prank(owner);
        oracle.updateProviderConfig(newConfig, "");

        // Submit with INITIAL_CONFIG -- should still be accepted
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_patternProofType_skipsConfigValidation() public {
        // PATTERN (0x03) should not validate config hash
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)) // tx_set_hash
        );
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_isValidConfig() public view {
        assertTrue(oracle.isValidConfig(INITIAL_CONFIG));
        assertFalse(oracle.isValidConfig(bytes32(uint256(0xdead))));
    }

    // -------------------------------------------------------------------------
    // Fuzz tests
    // -------------------------------------------------------------------------

    function testFuzz_updateAttestationTTL_validRange(uint256 ttl) public {
        ttl = bound(ttl, 1 hours, 30 days);
        vm.prank(owner);
        oracle.updateAttestationTTL(ttl);
        assertEq(oracle.attestationTTL(), ttl);
    }

    function testFuzz_updateAttestationTTL_revert_outOfRange(uint256 ttl) public {
        vm.assume(ttl < 1 hours || ttl > 30 days);
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.InvalidTTL.selector);
        oracle.updateAttestationTTL(ttl);
    }

    function testFuzz_checkCompliance_expiryBoundary(uint256 elapsed) public {
        elapsed = bound(elapsed, 0, 48 hours);
        _submitForAlice(0);

        vm.warp(block.timestamp + elapsed);
        (bool valid,) = oracle.checkCompliance(alice, 0);

        if (elapsed <= 24 hours) {
            assertTrue(valid);
        } else {
            assertFalse(valid);
        }
    }

    function testFuzz_submitCompliance_revert_invalidJurisdiction(uint8 j) public {
        vm.assume(j > 3);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(JurisdictionConfig.InvalidJurisdiction.selector, j));
        oracle.submitCompliance(
            j,
            ProofTypes.COMPLIANCE,
            _uniqueProof(),
            _complianceInputsFor(j, DEFAULT_PROVIDER_SET_HASH),
            DEFAULT_PROVIDER_SET_HASH
        );
    }

    function testFuzz_providerConfigVersioning(uint8 numUpdates) public {
        numUpdates = uint8(bound(numUpdates, 1, 20));
        vm.startPrank(owner);
        for (uint8 i; i < numUpdates; i++) {
            bytes32 config = keccak256(abi.encodePacked("config-", i));
            oracle.updateProviderConfig(config, "");
        }
        vm.stopPrank();

        // +1 for initial config
        assertEq(oracle.configHistoryLength(), uint256(numUpdates) + 1);
    }

    // -------------------------------------------------------------------------
    // Finding 1: Unaligned public inputs
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_nonAlignedPublicInputs() public {
        // 161 bytes = 5*32 + 1 -- extra trailing byte
        // Build valid compliance inputs then append one byte
        bytes memory aligned = _complianceInputs();
        bytes memory unaligned = abi.encodePacked(aligned, uint8(0xff));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 161));
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), unaligned, DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Finding 2: Input validation for all proof types
    // -------------------------------------------------------------------------

    function test_submitCompliance_membershipProof_revert_unregisteredMerkleRoot() public {
        bytes memory publicInputs = _membershipInputs(bytes32(uint256(0xdead)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidMerkleRoot.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_membershipProof_registeredRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        bytes memory publicInputs = _membershipInputs(root);
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att =
            oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
        assertEq(att.subject, alice);
    }

    function test_submitCompliance_nonMembershipProof_revert_unregisteredMerkleRoot() public {
        bytes memory publicInputs = _nonMembershipInputs(bytes32(uint256(0xdead)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidMerkleRoot.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.NON_MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_attestationProof_revert_unregisteredMerkleRoot() public {
        bytes memory publicInputs = _attestationInputs(bytes32(uint256(0xdead)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidMerkleRoot.selector, bytes32(uint256(0xdead))));
        oracle.submitCompliance(0, ProofTypes.ATTESTATION, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_patternProof_revert_zeroTxSetHash() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0)) // tx_set_hash = 0 (invalid)
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.PublicInputMismatch.selector);
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // F1: Reject proofs with negative result fields
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_complianceNonCompliant() public {
        // meets_threshold = 0 (non-compliant)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id
            DEFAULT_PROVIDER_SET_HASH, // provider_set_hash
            INITIAL_CONFIG, // config_hash
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(0)) // meets_threshold = false
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, _uniqueProof(), publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_riskScoreNegativeResult() public {
        // result = 0 (score doesn't satisfy condition)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // proof_type
            bytes32(uint256(1)), // direction
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(0)), // result = false
            INITIAL_CONFIG, // config_hash
            bytes32(uint256(0xeeff)) // provider_set_hash
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.RISK_SCORE, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_patternStructuringDetected() public {
        // result = 0 (structuring detected)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(0)), // result = false (structuring detected)
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)) // tx_set_hash
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_attestationInvalid() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        // is_valid = 0 (credential invalid/expired)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(42)), // provider_id
            bytes32(uint256(1)), // credential_type
            bytes32(uint256(0)), // is_valid = false
            root, // merkle_root
            bytes32(uint256(1700000)) // current_timestamp
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.ATTESTATION, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_membershipNotMember() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        // is_member = 0 (not a member)
        bytes memory publicInputs = abi.encodePacked(
            root, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(0)) // is_member = false
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_submitCompliance_revert_nonMembershipFailed() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        oracle.registerMerkleRoot(root);

        // is_non_member = 0 (element IS in set)
        bytes memory publicInputs = abi.encodePacked(
            root, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(0)) // is_non_member = false
        );
        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(0, ProofTypes.NON_MEMBERSHIP, _uniqueProof(), publicInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Finding 5: Proof replay across proof types
    // -------------------------------------------------------------------------

    function test_submitCompliance_proofReplayAcrossTypes_allowed() public {
        // Same proof bytes submitted for two different proof types should succeed
        // because proofHash is keyed on (proof, proofType)
        bytes memory proof = _uniqueProof();

        // Submit as COMPLIANCE
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Same proof bytes as PATTERN should succeed (different proofType in hash)
        bytes memory patternInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)) // tx_set_hash
        );
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.PATTERN, proof, patternInputs, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Finding 6: TTL boundary precision
    // -------------------------------------------------------------------------

    function test_checkCompliance_validAtExactExpiry() public {
        _submitForAlice(0);
        // warp to exactly expiresAt (block.timestamp + 24 hours)
        vm.warp(block.timestamp + 24 hours);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertTrue(valid); // <= means valid at exact boundary
    }

    function test_checkCompliance_invalidOneSecondAfterExpiry() public {
        _submitForAlice(0);
        vm.warp(block.timestamp + 24 hours + 1);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    // -------------------------------------------------------------------------
    // Finding 11: Config revocation
    // -------------------------------------------------------------------------

    function test_revokeConfig_preventsSubmission() public {
        // Add a second config, then revoke the initial one
        bytes32 newConfig = keccak256("new-config");
        vm.startPrank(owner);
        oracle.updateProviderConfig(newConfig, "");
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        // Submit with revoked INITIAL_CONFIG should fail
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, INITIAL_CONFIG));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_revokeConfig_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.revokeConfig(INITIAL_CONFIG);
    }

    function test_revokeConfig_revert_cannotRevokeCurrent() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.CannotRevokeCurrentConfig.selector);
        oracle.revokeConfig(INITIAL_CONFIG);
    }

    // -------------------------------------------------------------------------
    // Merkle root registry
    // -------------------------------------------------------------------------

    function test_registerMerkleRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit IXochiZKPOracle.MerkleRootRegistered(root);
        oracle.registerMerkleRoot(root);
        assertTrue(oracle.isValidMerkleRoot(root));
    }

    function test_revokeMerkleRoot() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.startPrank(owner);
        oracle.registerMerkleRoot(root);
        oracle.revokeMerkleRoot(root);
        vm.stopPrank();
        assertFalse(oracle.isValidMerkleRoot(root));
    }

    function test_registerMerkleRoot_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.registerMerkleRoot(bytes32(uint256(0xbeef)));
    }

    // -------------------------------------------------------------------------
    // PATTERN reporting threshold validation
    // -------------------------------------------------------------------------

    function test_submitCompliance_patternProof_revert_unregisteredThreshold() public {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)), // analysis_type
            bytes32(uint256(1)), // result
            bytes32(uint256(99999)), // reporting_threshold (not registered)
            bytes32(uint256(86400)), // time_window
            bytes32(uint256(0xabcd)) // tx_set_hash
        );
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(XochiZKPOracle.InvalidReportingThreshold.selector, bytes32(uint256(99999)))
        );
        oracle.submitCompliance(0, ProofTypes.PATTERN, _uniqueProof(), publicInputs, bytes32(0));
    }

    function test_registerReportingThreshold_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.registerReportingThreshold(bytes32(uint256(20000)));
    }

    function test_revokeReportingThreshold() public {
        bytes32 threshold = bytes32(uint256(10000));
        vm.prank(owner);
        oracle.revokeReportingThreshold(threshold);
        assertFalse(oracle.isValidReportingThreshold(threshold));
    }

    // -------------------------------------------------------------------------
    // TOCTOU: view verifier prevents reentrancy
    // -------------------------------------------------------------------------

    function test_submitCompliance_viewVerifierPreventsReentrancy() public {
        // After the view fix, the verifier's verify() is view, so it cannot
        // call back into setVerifier(). This test confirms verifierUsed matches
        // the actual verifier used for verification by checking consistency
        // across a verifier upgrade scenario.
        bytes memory proof1 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att1 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof1, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Upgrade verifier mid-session
        AlwaysPassVerifier newStub = new AlwaysPassVerifier();
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(newStub));

        bytes memory proof2 = _uniqueProof();
        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att2 =
            oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof2, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        // Each attestation records the verifier that was actually used
        assertEq(att1.verifierUsed, address(stubVerifier));
        assertEq(att2.verifierUsed, address(newStub));
        assertTrue(att1.verifierUsed != att2.verifierUsed);
    }

    // -------------------------------------------------------------------------
    // Ownership edge case (Oracle)
    // -------------------------------------------------------------------------

    function test_transferOwnership_revert_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        oracle.transferOwnership(address(0));
    }

    // -------------------------------------------------------------------------
    // Additional fuzz tests
    // -------------------------------------------------------------------------

    function testFuzz_publicInputEncoding_roundTrips(bytes32 a, bytes32 b, bytes32 c) public pure {
        // Verify that abi.encodePacked produces correctly aligned 32-byte slots
        bytes memory packed = abi.encodePacked(a, b, c);
        assertEq(packed.length, 96);
        assertEq(packed.length % 32, 0);
        // Verify individual slots via direct memory reads
        bytes32 slot0;
        bytes32 slot1;
        bytes32 slot2;
        assembly {
            slot0 := mload(add(packed, 32))
            slot1 := mload(add(packed, 64))
            slot2 := mload(add(packed, 96))
        }
        assertEq(slot0, a);
        assertEq(slot1, b);
        assertEq(slot2, c);
    }

    function testFuzz_proofHash_uniquePerType(bytes memory proof, uint8 typeA, uint8 typeB) public pure {
        vm.assume(typeA != typeB);
        bytes32 hashA = keccak256(abi.encodePacked(proof, typeA));
        bytes32 hashB = keccak256(abi.encodePacked(proof, typeB));
        assertTrue(hashA != hashB);
    }

    function testFuzz_submitCompliance_allProofTypes(uint8 proofType) public {
        proofType = uint8(bound(proofType, 1, 6));
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs;

        if (proofType == ProofTypes.COMPLIANCE) {
            publicInputs = _complianceInputs();
        } else if (proofType == ProofTypes.RISK_SCORE) {
            publicInputs = _riskScoreInputs(INITIAL_CONFIG);
        } else if (proofType == ProofTypes.PATTERN) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(1)),
                bytes32(uint256(10000)),
                bytes32(uint256(86400)),
                bytes32(uint256(0xabcd))
            );
        } else if (proofType == ProofTypes.ATTESTATION) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = _attestationInputs(root);
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = _membershipInputs(root);
        } else {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = _nonMembershipInputs(root);
        }

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0,
            proofType,
            proof,
            publicInputs,
            proofType == ProofTypes.COMPLIANCE ? DEFAULT_PROVIDER_SET_HASH : bytes32(0)
        );
        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, 0);
        assertTrue(att.meetsThreshold);
    }

    // -------------------------------------------------------------------------
    // Stateful invariant properties
    // -------------------------------------------------------------------------

    function testFuzz_expiredAttestationNeverValid(uint256 elapsed) public {
        elapsed = bound(elapsed, 24 hours + 1, 365 days);
        _submitForAlice(0);
        vm.warp(block.timestamp + elapsed);
        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertFalse(valid);
    }

    function testFuzz_replayAlwaysReverts(uint8 jurisdictionId) public {
        jurisdictionId = uint8(bound(jurisdictionId, 0, 3));
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);

        // Replay with same proof and same type always reverts
        vm.prank(alice);
        bytes32 expectedHash = keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE));
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.ProofAlreadyUsed.selector, expectedHash));
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    function testFuzz_attestationFieldsConsistent(uint8 jurisdictionId) public {
        jurisdictionId = uint8(bound(jurisdictionId, 0, 3));
        bytes memory proof = _uniqueProof();
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH
        );

        // Attestation fields must be internally consistent
        assertEq(att.subject, alice);
        assertEq(att.jurisdictionId, jurisdictionId);
        assertTrue(att.meetsThreshold);
        assertEq(att.expiresAt, att.timestamp + oracle.attestationTTL());
        assertEq(att.proofHash, keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE)));
        assertEq(att.publicInputsHash, keccak256(publicInputs));
        assertEq(att.providerSetHash, DEFAULT_PROVIDER_SET_HASH);
        assertTrue(att.verifierUsed != address(0));

        // Stored attestation must match returned attestation
        (bool valid, IXochiZKPOracle.ComplianceAttestation memory stored) =
            oracle.checkCompliance(alice, jurisdictionId);
        assertTrue(valid);
        assertEq(stored.proofHash, att.proofHash);
        assertEq(stored.verifierUsed, att.verifierUsed);
    }

    function testFuzz_revokedConfigBlocksSubmission(bytes32 newConfig) public {
        vm.assume(newConfig != INITIAL_CONFIG && newConfig != bytes32(0));

        vm.startPrank(owner);
        oracle.updateProviderConfig(newConfig, "");
        oracle.revokeConfig(INITIAL_CONFIG);
        vm.stopPrank();

        // Proof using revoked config must fail
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, INITIAL_CONFIG));
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    // -------------------------------------------------------------------------
    // Pause mechanism
    // -------------------------------------------------------------------------

    function test_pause_blocksSubmitCompliance() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(alice);
        vm.expectRevert(Pausable.ContractPaused.selector);
        oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
    }

    function test_pause_allowsCheckCompliance() public {
        _submitForAlice(0);
        vm.prank(owner);
        oracle.pause();

        (bool valid,) = oracle.checkCompliance(alice, 0);
        assertTrue(valid);
    }

    function test_pause_allowsGetHistoricalProof() public {
        bytes memory proof = _uniqueProof();
        vm.prank(alice);
        oracle.submitCompliance(0, ProofTypes.COMPLIANCE, proof, _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);

        vm.prank(owner);
        oracle.pause();

        bytes32 proofHash = keccak256(abi.encodePacked(proof, ProofTypes.COMPLIANCE));
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.getHistoricalProof(proofHash);
        assertEq(att.subject, alice);
    }

    function test_unpause_resumesSubmitCompliance() public {
        vm.startPrank(owner);
        oracle.pause();
        oracle.unpause();
        vm.stopPrank();

        vm.prank(alice);
        IXochiZKPOracle.ComplianceAttestation memory att = oracle.submitCompliance(
            0, ProofTypes.COMPLIANCE, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH
        );
        assertEq(att.subject, alice);
    }

    function test_pause_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.pause();
    }

    function test_unpause_revert_notOwner() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        oracle.unpause();
    }

    function test_pause_revert_alreadyPaused() public {
        vm.startPrank(owner);
        oracle.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        oracle.pause();
        vm.stopPrank();
    }

    function test_unpause_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(Pausable.ContractNotPaused.selector);
        oracle.unpause();
    }

    function test_pause_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Paused(owner);
        oracle.pause();
    }

    function test_unpause_emitsEvent() public {
        vm.prank(owner);
        oracle.pause();

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Unpaused(owner);
        oracle.unpause();
    }

    // -------------------------------------------------------------------------
    // Config history bounds
    // -------------------------------------------------------------------------

    function test_updateProviderConfig_revert_historyFull() public {
        vm.startPrank(owner);
        // setUp already pushed 1 (initial config). Push 255 more to reach 256.
        for (uint256 i; i < 255; i++) {
            oracle.updateProviderConfig(keccak256(abi.encodePacked("fill-", i)), "");
        }
        assertEq(oracle.configHistoryLength(), 256);

        // 257th should revert
        vm.expectRevert(XochiZKPOracle.ConfigHistoryFull.selector);
        oracle.updateProviderConfig(keccak256("overflow"), "");
        vm.stopPrank();
    }

    function test_updateProviderConfig_revert_duplicateConfig() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.ConfigAlreadyCurrent.selector);
        oracle.updateProviderConfig(INITIAL_CONFIG, "");
    }

    // -------------------------------------------------------------------------
    // Constructor: zero config hash
    // -------------------------------------------------------------------------

    function test_constructor_revert_zeroConfigHash() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPOracle.InvalidConfigHash.selector, bytes32(0)));
        new XochiZKPOracle(address(verifier), owner, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Idempotency guards
    // -------------------------------------------------------------------------

    function test_registerMerkleRoot_revert_alreadyRegistered() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.startPrank(owner);
        oracle.registerMerkleRoot(root);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.registerMerkleRoot(root);
        vm.stopPrank();
    }

    function test_revokeMerkleRoot_revert_notRegistered() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.revokeMerkleRoot(bytes32(uint256(0xdead)));
    }

    function test_registerReportingThreshold_revert_alreadyRegistered() public {
        // 10000 already registered in setUp
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.AlreadyRegistered.selector);
        oracle.registerReportingThreshold(bytes32(uint256(10000)));
    }

    function test_revokeReportingThreshold_revert_notRegistered() public {
        vm.prank(owner);
        vm.expectRevert(XochiZKPOracle.NotRegistered.selector);
        oracle.revokeReportingThreshold(bytes32(uint256(99999)));
    }

    // -------------------------------------------------------------------------
    // Unknown proof type guard
    // -------------------------------------------------------------------------

    function test_submitCompliance_revert_unknownProofType_zero() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x00));
        oracle.submitCompliance(0, 0x00, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    function test_submitCompliance_revert_unknownProofType_seven() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x07));
        oracle.submitCompliance(0, 0x07, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Ownership transfer cancellation
    // -------------------------------------------------------------------------

    function test_transferOwnership_emitsCancellation_whenPendingExists() public {
        address bob = makeAddr("bob");
        vm.startPrank(owner);
        oracle.transferOwnership(alice);

        vm.expectEmit(true, false, false, false);
        emit Ownable2Step.OwnershipTransferCancelled(alice);
        oracle.transferOwnership(bob);
        vm.stopPrank();
    }

    function test_transferOwnership_noCancellation_whenNoPending() public {
        // First transfer should not emit cancellation
        vm.prank(owner);
        vm.recordLogs();
        oracle.transferOwnership(alice);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        for (uint256 i; i < entries.length; i++) {
            assertTrue(
                entries[i].topics[0] != keccak256("OwnershipTransferCancelled(address)"), "should not emit cancellation"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Fuzz: negative result fields always revert
    // -------------------------------------------------------------------------

    function testFuzz_submitCompliance_revert_negativeResult_allTypes(uint8 proofType) public {
        proofType = uint8(bound(proofType, 1, 6));
        bytes memory publicInputs;

        if (proofType == ProofTypes.COMPLIANCE) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(0)),
                DEFAULT_PROVIDER_SET_HASH,
                INITIAL_CONFIG,
                bytes32(uint256(1700000)),
                bytes32(uint256(0)) // meets_threshold = 0
            );
        } else if (proofType == ProofTypes.RISK_SCORE) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(1)),
                bytes32(uint256(5000)),
                bytes32(uint256(0)),
                bytes32(uint256(0)),
                INITIAL_CONFIG, // result = 0
                bytes32(uint256(0xeeff)) // provider_set_hash
            );
        } else if (proofType == ProofTypes.PATTERN) {
            publicInputs = abi.encodePacked(
                bytes32(uint256(1)),
                bytes32(uint256(0)), // result = 0
                bytes32(uint256(10000)),
                bytes32(uint256(86400)),
                bytes32(uint256(0xabcd))
            );
        } else if (proofType == ProofTypes.ATTESTATION) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = abi.encodePacked(
                bytes32(uint256(42)),
                bytes32(uint256(1)),
                bytes32(uint256(0)),
                root,
                bytes32(uint256(1700000)) // is_valid = 0
            );
        } else if (proofType == ProofTypes.MEMBERSHIP) {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = abi.encodePacked(
                root,
                bytes32(uint256(1)),
                bytes32(uint256(1700000)),
                bytes32(uint256(0)) // is_member = 0
            );
        } else {
            bytes32 root = bytes32(uint256(0xbeef));
            vm.prank(owner);
            oracle.registerMerkleRoot(root);
            publicInputs = abi.encodePacked(
                root,
                bytes32(uint256(1)),
                bytes32(uint256(1700000)),
                bytes32(uint256(0)) // is_non_member = 0
            );
        }

        vm.prank(alice);
        vm.expectRevert(XochiZKPOracle.ProofResultNegative.selector);
        oracle.submitCompliance(
            0,
            proofType,
            _uniqueProof(),
            publicInputs,
            proofType == ProofTypes.COMPLIANCE ? DEFAULT_PROVIDER_SET_HASH : bytes32(0)
        );
    }

    function testFuzz_submitCompliance_revert_unknownProofType(uint8 proofType) public {
        vm.assume(proofType == 0 || proofType > 6);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        oracle.submitCompliance(0, proofType, _uniqueProof(), _complianceInputs(), DEFAULT_PROVIDER_SET_HASH);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _submitForAlice(uint8 jurisdictionId) internal {
        _submitForAliceWith(jurisdictionId, _uniqueProof());
    }

    function _submitForAliceWith(uint8 jurisdictionId, bytes memory proof) internal {
        bytes memory publicInputs = _complianceInputsFor(jurisdictionId, DEFAULT_PROVIDER_SET_HASH);
        vm.prank(alice);
        oracle.submitCompliance(jurisdictionId, ProofTypes.COMPLIANCE, proof, publicInputs, DEFAULT_PROVIDER_SET_HASH);
    }

    uint256 internal _proofNonce;

    function _uniqueProof() internal returns (bytes memory) {
        _proofNonce++;
        bytes memory proof = new bytes(2144);
        assembly {
            mstore(add(proof, 32), sload(_proofNonce.slot))
        }
        // Use storage nonce encoded in the proof to make it unique
        bytes32 nonceBytes = bytes32(_proofNonce);
        for (uint256 i; i < 32; i++) {
            proof[i] = nonceBytes[i];
        }
        return proof;
    }

    function _dummyProof() internal pure returns (bytes memory) {
        return new bytes(2144);
    }

    /// @dev Default provider set hash used in tests (must match public inputs)
    bytes32 internal constant DEFAULT_PROVIDER_SET_HASH = bytes32(uint256(0xaabb));

    /// @dev 5 public inputs matching the compliance circuit
    function _complianceInputs() internal pure returns (bytes memory) {
        return _complianceInputsFor(0, DEFAULT_PROVIDER_SET_HASH);
    }

    /// @dev Compliance inputs with configurable jurisdiction and providerSetHash
    function _complianceInputsFor(uint8 jurisdictionId, bytes32 providerSetHash) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(jurisdictionId)), // jurisdiction_id
            providerSetHash, // provider_set_hash
            INITIAL_CONFIG, // config_hash
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // meets_threshold
        );
    }

    /// @dev RISK_SCORE public inputs with configurable config hash
    function _riskScoreInputs(bytes32 configHash) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper
            bytes32(uint256(1)), // result
            configHash, // config_hash
            bytes32(uint256(0xeeff)) // provider_set_hash
        );
    }

    /// @dev MEMBERSHIP public inputs with configurable merkle root
    function _membershipInputs(bytes32 merkleRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // is_member
        );
    }

    /// @dev NON_MEMBERSHIP public inputs with configurable merkle root
    function _nonMembershipInputs(bytes32 merkleRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(
            merkleRoot, // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // is_non_member
        );
    }

    /// @dev ATTESTATION public inputs with configurable merkle root
    function _attestationInputs(bytes32 merkleRoot) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(42)), // provider_id
            bytes32(uint256(1)), // credential_type
            bytes32(uint256(1)), // is_valid
            merkleRoot, // merkle_root
            bytes32(uint256(1700000)) // current_timestamp
        );
    }
}
