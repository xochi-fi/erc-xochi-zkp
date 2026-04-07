// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {XochiZKPVerifier} from "../src/XochiZKPVerifier.sol";
import {XochiZKPOracle} from "../src/XochiZKPOracle.sol";
import {ProofTypes} from "../src/libraries/ProofTypes.sol";

/// @title Deploy -- Deployment script for Xochi ZKP contracts
/// @notice Deploys the verifier router, oracle, and all 6 generated UltraHonk
///         verifier contracts, then registers each verifier with the router.
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
///
/// Environment variables:
///   PRIVATE_KEY          -- deployer private key
///   INITIAL_CONFIG_HASH  -- initial provider weight config hash (optional, defaults to zero)
contract Deploy is Script {
    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        bytes32 configHash = vm.envOr("INITIAL_CONFIG_HASH", bytes32(0));

        console.log("Deployer:", deployer);
        console.log("Initial config hash:");
        console.logBytes32(configHash);

        vm.startBroadcast(deployerKey);

        // 1. Deploy the verifier router
        XochiZKPVerifier verifier = new XochiZKPVerifier(deployer);
        console.log("XochiZKPVerifier:", address(verifier));

        // 2. Deploy the oracle
        XochiZKPOracle oracle = new XochiZKPOracle(address(verifier), deployer, configHash);
        console.log("XochiZKPOracle:", address(oracle));

        // 3. Deploy generated UltraHonk verifiers and register them
        _deployAndRegister(verifier, ProofTypes.COMPLIANCE, "ComplianceVerifier");
        _deployAndRegister(verifier, ProofTypes.RISK_SCORE, "RiskScoreVerifier");
        _deployAndRegister(verifier, ProofTypes.PATTERN, "AntiStructuringVerifier");
        _deployAndRegister(verifier, ProofTypes.ATTESTATION, "TierVerificationVerifier");
        _deployAndRegister(verifier, ProofTypes.MEMBERSHIP, "MembershipVerifier");
        _deployAndRegister(verifier, ProofTypes.NON_MEMBERSHIP, "NonMembershipVerifier");

        vm.stopBroadcast();
    }

    function _deployAndRegister(XochiZKPVerifier verifier, uint8 proofType, string memory contractName) internal {
        string memory artifact = string.concat(_artifactFileName(contractName), ":", contractName);
        bytes memory bytecode = vm.getCode(artifact);

        address deployed;
        assembly {
            deployed := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(deployed != address(0), string.concat(contractName, " deployment failed"));

        verifier.setVerifier(proofType, deployed);
        console.log(string.concat("  ", contractName, ":"), deployed);
    }

    function _artifactFileName(string memory contractName) internal pure returns (string memory) {
        if (keccak256(bytes(contractName)) == keccak256("ComplianceVerifier")) {
            return "compliance_verifier.sol";
        }
        if (keccak256(bytes(contractName)) == keccak256("RiskScoreVerifier")) {
            return "risk_score_verifier.sol";
        }
        if (keccak256(bytes(contractName)) == keccak256("AntiStructuringVerifier")) {
            return "anti_structuring_verifier.sol";
        }
        if (keccak256(bytes(contractName)) == keccak256("TierVerificationVerifier")) {
            return "tier_verification_verifier.sol";
        }
        if (keccak256(bytes(contractName)) == keccak256("MembershipVerifier")) {
            return "membership_verifier.sol";
        }
        if (keccak256(bytes(contractName)) == keccak256("NonMembershipVerifier")) {
            return "non_membership_verifier.sol";
        }
        revert("unknown contract");
    }
}
