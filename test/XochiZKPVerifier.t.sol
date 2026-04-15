// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {IUltraVerifier} from "../src/interfaces/IUltraVerifier.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";
import {Ownable2Step} from "../src/libraries/Ownable2Step.sol";
import {Pausable} from "../src/libraries/Pausable.sol";

/// @dev Stub verifier that always returns true (for unit testing the router logic)
contract StubVerifier is IUltraVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return shouldPass;
    }
}

contract XochiZKPVerifierTest is Test {
    XochiZKPVerifier internal verifier;
    StubVerifier internal passingVerifier;
    StubVerifier internal failingVerifier;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");

    function setUp() public {
        verifier = new XochiZKPVerifier(owner);
        passingVerifier = new StubVerifier(true);
        failingVerifier = new StubVerifier(false);

        vm.startPrank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(passingVerifier));
        verifier.setVerifier(ProofTypes.RISK_SCORE, address(passingVerifier));
        verifier.setVerifier(ProofTypes.PATTERN, address(passingVerifier));
        verifier.setVerifier(ProofTypes.ATTESTATION, address(passingVerifier));
        verifier.setVerifier(ProofTypes.MEMBERSHIP, address(passingVerifier));
        verifier.setVerifier(ProofTypes.NON_MEMBERSHIP, address(passingVerifier));
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_constructor_setsOwner() public view {
        assertEq(verifier.owner(), owner);
    }

    function test_constructor_revert_zeroAddress() public {
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        new XochiZKPVerifier(address(0));
    }

    // -------------------------------------------------------------------------
    // verifyProof
    // -------------------------------------------------------------------------

    function test_verifyProof_compliance_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_verifyProof_riskScore_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.RISK_SCORE, _dummyProof(), _riskScoreInputs()));
    }

    function test_verifyProof_pattern_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.PATTERN, _dummyProof(), _patternInputs()));
    }

    function test_verifyProof_attestation_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.ATTESTATION, _dummyProof(), _attestationInputs()));
    }

    function test_verifyProof_membership_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.MEMBERSHIP, _dummyProof(), _membershipInputs()));
    }

    function test_verifyProof_nonMembership_valid() public {
        assertTrue(verifier.verifyProof(ProofTypes.NON_MEMBERSHIP, _dummyProof(), _nonMembershipInputs()));
    }

    function test_verifyProof_revert_invalidProofType() public {
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x00));
        verifier.verifyProof(0x00, _dummyProof(), _complianceInputs());

        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x07));
        verifier.verifyProof(0x07, _dummyProof(), _complianceInputs());
    }

    function test_verifyProof_revert_verifierNotSet() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.VerifierNotSet.selector, ProofTypes.COMPLIANCE));
        fresh.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_verifyProof_revert_wrongPublicInputCount() public {
        // Compliance expects 5 inputs, give it 3
        bytes memory badInputs = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)), bytes32(uint256(3)));

        vm.expectRevert(
            abi.encodeWithSelector(ProofTypes.InvalidPublicInputLength.selector, ProofTypes.COMPLIANCE, 5, 3)
        );
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), badInputs);
    }

    function test_verifyProof_failingVerifier() public {
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    // -------------------------------------------------------------------------
    // verifyProofBatch
    // -------------------------------------------------------------------------

    function test_verifyProofBatch_allValid() public {
        uint8[] memory types = new uint8[](2);
        types[0] = ProofTypes.COMPLIANCE;
        types[1] = ProofTypes.RISK_SCORE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _dummyProof();
        proofs[1] = _dummyProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs();

        assertTrue(verifier.verifyProofBatch(types, proofs, inputs));
    }

    function test_verifyProofBatch_oneFails() public {
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        uint8[] memory types = new uint8[](2);
        types[0] = ProofTypes.COMPLIANCE;
        types[1] = ProofTypes.RISK_SCORE;

        bytes[] memory proofs = new bytes[](2);
        proofs[0] = _dummyProof();
        proofs[1] = _dummyProof();

        bytes[] memory inputs = new bytes[](2);
        inputs[0] = _complianceInputs();
        inputs[1] = _riskScoreInputs();

        assertFalse(verifier.verifyProofBatch(types, proofs, inputs));
    }

    function test_verifyProofBatch_revert_emptyBatch() public {
        vm.expectRevert(XochiZKPVerifier.EmptyBatch.selector);
        verifier.verifyProofBatch(new uint8[](0), new bytes[](0), new bytes[](0));
    }

    function test_verifyProofBatch_revert_batchTooLarge() public {
        uint256 size = verifier.MAX_BATCH_SIZE() + 1;
        uint8[] memory types = new uint8[](size);
        bytes[] memory proofs = new bytes[](size);
        bytes[] memory inputs = new bytes[](size);

        vm.expectRevert(XochiZKPVerifier.BatchTooLarge.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    function test_verifyProofBatch_revert_lengthMismatch() public {
        uint8[] memory types = new uint8[](2);
        bytes[] memory proofs = new bytes[](1);
        bytes[] memory inputs = new bytes[](2);

        vm.expectRevert(XochiZKPVerifier.BatchLengthMismatch.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    // -------------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------------

    function test_setVerifier_updatesAddress() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, newVerifier);
        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), newVerifier);
    }

    function test_setVerifier_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(passingVerifier));
    }

    function test_setVerifier_revert_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(Ownable2Step.ZeroAddress.selector);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(0));
    }

    function test_setVerifier_revert_invalidProofType() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, 0x07));
        verifier.setVerifier(0x07, address(passingVerifier));
    }

    function test_setVerifier_emitsEvent() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierUpdated(ProofTypes.COMPLIANCE, address(passingVerifier), newVerifier);
        verifier.setVerifier(ProofTypes.COMPLIANCE, newVerifier);
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    function test_transferOwnership_twoStep() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);
        assertEq(verifier.pendingOwner(), alice);
        assertEq(verifier.owner(), owner);

        vm.prank(alice);
        verifier.acceptOwnership();
        assertEq(verifier.owner(), alice);
        assertEq(verifier.pendingOwner(), address(0));
    }

    function test_transferOwnership_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        verifier.transferOwnership(alice);
    }

    function test_acceptOwnership_revert_notPending() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);

        vm.prank(makeAddr("bob"));
        vm.expectRevert(Ownable2Step.NotPendingOwner.selector);
        verifier.acceptOwnership();
    }

    function test_acceptOwnership_revert_expired() public {
        vm.prank(owner);
        verifier.transferOwnership(alice);

        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(alice);
        vm.expectRevert(Ownable2Step.OwnershipTransferExpired.selector);
        verifier.acceptOwnership();
    }

    // -------------------------------------------------------------------------
    // Verifier upgrade scenarios
    // -------------------------------------------------------------------------

    function test_verifierUpgrade_newVerifierUsed() public {
        // Start with passing verifier, upgrade to failing
        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));

        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_verifierUpgrade_otherTypesUnaffected() public {
        // Upgrade only COMPLIANCE, others should still pass
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        assertFalse(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
        assertTrue(verifier.verifyProof(ProofTypes.RISK_SCORE, _dummyProof(), _riskScoreInputs()));
        assertTrue(verifier.verifyProof(ProofTypes.MEMBERSHIP, _dummyProof(), _membershipInputs()));
    }

    function test_verifierUpgrade_emitsOldAndNew() public {
        address newVerifier = makeAddr("newVerifier");
        vm.prank(owner);

        vm.expectEmit(true, true, true, true);
        emit XochiZKPVerifier.VerifierUpdated(ProofTypes.COMPLIANCE, address(passingVerifier), newVerifier);
        verifier.setVerifier(ProofTypes.COMPLIANCE, newVerifier);
    }

    // -------------------------------------------------------------------------
    // Verifier history
    // -------------------------------------------------------------------------

    function test_setVerifier_buildsHistory() public {
        // setUp already called setVerifier for each type (version 1)
        assertEq(verifier.getVerifierVersion(ProofTypes.COMPLIANCE), 1);
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 1), address(passingVerifier));

        // Upgrade to version 2
        address v2 = makeAddr("v2Verifier");
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, v2);

        assertEq(verifier.getVerifierVersion(ProofTypes.COMPLIANCE), 2);
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 1), address(passingVerifier));
        assertEq(verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 2), v2);
    }

    function test_verifyProofAtVersion_routesToHistorical() public {
        // Upgrade COMPLIANCE to failing verifier (version 2)
        vm.prank(owner);
        verifier.setVerifier(ProofTypes.COMPLIANCE, address(failingVerifier));

        // Version 1 (passing) should still return true
        assertTrue(verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs()));
        // Version 2 (failing) should return false
        assertFalse(verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 2, _dummyProof(), _complianceInputs()));
    }

    function test_getVerifierAtVersion_revert_invalidVersion() public {
        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 0));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 0);

        vm.expectRevert(abi.encodeWithSelector(XochiZKPVerifier.InvalidVersion.selector, ProofTypes.COMPLIANCE, 99));
        verifier.getVerifierAtVersion(ProofTypes.COMPLIANCE, 99);
    }

    function test_getVerifierVersion_noVerifierSet() public {
        XochiZKPVerifier fresh = new XochiZKPVerifier(owner);
        assertEq(fresh.getVerifierVersion(ProofTypes.COMPLIANCE), 0);
    }

    // -------------------------------------------------------------------------
    // Fuzz: proof type validation
    // -------------------------------------------------------------------------

    function testFuzz_verifyProof_revert_invalidProofType(uint8 proofType) public {
        vm.assume(proofType == 0 || proofType > 6);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.verifyProof(proofType, _dummyProof(), _complianceInputs());
    }

    function testFuzz_setVerifier_revert_invalidProofType(uint8 proofType) public {
        vm.assume(proofType == 0 || proofType > 6);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.InvalidProofType.selector, proofType));
        verifier.setVerifier(proofType, address(passingVerifier));
    }

    // -------------------------------------------------------------------------
    // View correctness (Finding 3)
    // -------------------------------------------------------------------------

    function test_verifyProof_isView() public view {
        // After the view fix, verifyProof should be callable in a view context.
        // This test compiles only if the function signature is view.
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    // -------------------------------------------------------------------------
    // Unaligned public inputs (Finding 1)
    // -------------------------------------------------------------------------

    function test_verifyProof_revert_unalignedPublicInputs() public {
        bytes memory unaligned = new bytes(161); // 5*32 + 1
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 161));
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), unaligned);
    }

    function testFuzz_verifyProof_revert_unalignedPublicInputs(uint256 extra) public {
        extra = bound(extra, 1, 31);
        bytes memory unaligned = new bytes(5 * 32 + extra);
        vm.expectRevert(abi.encodeWithSelector(ProofTypes.UnalignedPublicInputs.selector, 5 * 32 + extra));
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), unaligned);
    }

    // -------------------------------------------------------------------------
    // Pause mechanism
    // -------------------------------------------------------------------------

    function test_pause_blocksVerifyProof() public {
        vm.prank(owner);
        verifier.pause();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs());
    }

    function test_pause_blocksVerifyProofBatch() public {
        vm.prank(owner);
        verifier.pause();

        uint8[] memory types = new uint8[](1);
        types[0] = ProofTypes.COMPLIANCE;
        bytes[] memory proofs = new bytes[](1);
        proofs[0] = _dummyProof();
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _complianceInputs();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProofBatch(types, proofs, inputs);
    }

    function test_pause_blocksVerifyProofAtVersion() public {
        vm.prank(owner);
        verifier.pause();

        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.verifyProofAtVersion(ProofTypes.COMPLIANCE, 1, _dummyProof(), _complianceInputs());
    }

    function test_pause_allowsGetVerifier() public {
        vm.prank(owner);
        verifier.pause();

        assertEq(verifier.getVerifier(ProofTypes.COMPLIANCE), address(passingVerifier));
    }

    function test_unpause_resumesVerifyProof() public {
        vm.startPrank(owner);
        verifier.pause();
        verifier.unpause();
        vm.stopPrank();

        assertTrue(verifier.verifyProof(ProofTypes.COMPLIANCE, _dummyProof(), _complianceInputs()));
    }

    function test_pause_revert_notOwner() public {
        vm.prank(alice);
        vm.expectRevert(Ownable2Step.Unauthorized.selector);
        verifier.pause();
    }

    function test_pause_revert_alreadyPaused() public {
        vm.startPrank(owner);
        verifier.pause();
        vm.expectRevert(Pausable.ContractPaused.selector);
        verifier.pause();
        vm.stopPrank();
    }

    function test_unpause_revert_notPaused() public {
        vm.prank(owner);
        vm.expectRevert(Pausable.ContractNotPaused.selector);
        verifier.unpause();
    }

    function test_pause_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Paused(owner);
        verifier.pause();
    }

    function test_unpause_emitsEvent() public {
        vm.prank(owner);
        verifier.pause();

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit Pausable.Unpaused(owner);
        verifier.unpause();
    }

    // -------------------------------------------------------------------------
    // Ownership transfer cancellation
    // -------------------------------------------------------------------------

    function test_transferOwnership_emitsCancellation_whenPendingExists() public {
        address bob = makeAddr("bob");
        vm.startPrank(owner);
        verifier.transferOwnership(alice);

        vm.expectEmit(true, false, false, false);
        emit Ownable2Step.OwnershipTransferCancelled(alice);
        verifier.transferOwnership(bob);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _dummyProof() internal pure returns (bytes memory) {
        return new bytes(2144);
    }

    /// @dev 5 public inputs: jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold
    function _complianceInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0)), // jurisdiction_id: EU
            bytes32(uint256(0xaabb)), // provider_set_hash
            bytes32(uint256(0xccdd)), // config_hash
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // meets_threshold: true
        );
    }

    /// @dev 7 public inputs: proof_type, direction, bound_lower, bound_upper, result, config_hash, provider_set_hash
    function _riskScoreInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // proof_type: threshold
            bytes32(uint256(1)), // direction: GT
            bytes32(uint256(5000)), // bound_lower
            bytes32(uint256(0)), // bound_upper (unused for threshold)
            bytes32(uint256(1)), // result: true
            bytes32(uint256(0xccdd)), // config_hash
            bytes32(uint256(0xeeff)) // provider_set_hash
        );
    }

    /// @dev 5 public inputs: analysis_type, result, reporting_threshold, time_window, tx_set_hash
    function _patternInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(1)), // analysis_type: structuring
            bytes32(uint256(1)), // result: clean
            bytes32(uint256(10000)), // reporting_threshold
            bytes32(uint256(3600)), // time_window
            bytes32(uint256(0xeeff)) // tx_set_hash
        );
    }

    /// @dev 5 public inputs: provider_id, credential_type, is_valid, merkle_root, current_timestamp
    function _attestationInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(42)), // provider_id
            bytes32(uint256(1)), // credential_type: KYC basic
            bytes32(uint256(1)), // is_valid: true
            bytes32(uint256(0xdead)), // merkle_root
            bytes32(uint256(1700000)) // current_timestamp
        );
    }

    /// @dev 4 public inputs: merkle_root, set_id, timestamp, is_member
    function _membershipInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0xabcd)), // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // is_member: true
        );
    }

    /// @dev 4 public inputs: merkle_root, set_id, timestamp, is_non_member
    function _nonMembershipInputs() internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(0xabcd)), // merkle_root
            bytes32(uint256(1)), // set_id
            bytes32(uint256(1700000)), // timestamp
            bytes32(uint256(1)) // is_non_member: true
        );
    }
}
