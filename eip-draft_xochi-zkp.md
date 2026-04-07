---
eip: TBD
title: Zero-Knowledge Compliance Oracle
description: On-chain verification of AML/sanctions compliance via zero-knowledge proofs without revealing transaction data
author: DROO (@Hydepwns), Bloo (@bloo-berries)
discussions-to: TBD
status: Draft
type: Standards Track
category: ERC
created: 2026-04-07
requires: 5564, 6538
---

## Abstract

A standard interface for on-chain verification of regulatory compliance (AML, sanctions screening, anti-structuring) using zero-knowledge proofs. Users generate proofs client-side that attest to compliance with jurisdiction-specific thresholds without revealing transaction amounts, counterparty identities, or screening details. Verifiers confirm proof validity on-chain. No trusted third party or TEE is required.

## Motivation

Public blockchains force a binary choice between transparency and privacy. Transparent execution (Uniswap, CoW Protocol) exposes trades to MEV extraction ($1.8B+ since the Merge). Privacy tools (Tornado Cash) have been sanctioned for lacking compliance mechanisms.

Existing approaches to compliant privacy fall short:

- **View keys** (Railgun, Panther): Trade privately, then reveal raw transaction data to auditors on request. This leaks the data. It's just delayed transparency.
- **TEE-based compliance** (various): Rely on hardware trust assumptions that have been broken repeatedly (SGX side channels, key extraction).
- **Compliance-by-exclusion** (Privacy Pools): Prove you're NOT in a bad set. Doesn't prove you ARE compliant with specific jurisdiction rules.

This ERC defines a standard where compliance is proven cryptographically at transaction time. The proof commits to screening results, jurisdiction thresholds, and provider attestations. Regulators verify a proof. They never see the underlying data.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Terminology

- **providerSetHash**: A commitment to the specific set of screening providers and their weights used for a particular compliance proof. Included in each attestation for retroactive verification.
- **providerConfigHash**: A hash of the global provider weight configuration published by the oracle administrator. Versioned on-chain; weight changes push a new entry to the config history.
- **attestation TTL**: The duration (in seconds) for which a compliance attestation remains valid after submission. Expired attestations remain queryable via `getHistoricalProof()` but are not considered valid by `checkCompliance()`.

### Proof Types

Implementations MUST support the following proof types. Each type corresponds to a separate ZK circuit with its own verification key.

| Type ID | Name           | Circuit           | Public inputs                                                                          | Private inputs                                                 |
| ------- | -------------- | ----------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| 0x01    | Compliance     | compliance        | jurisdiction_id, provider_set_hash, config_hash, timestamp, meets_threshold            | signals, weights, weight_sum, provider_ids, num_providers      |
| 0x02    | Risk Score     | risk_score        | proof_type (threshold/range), direction, bound_lower, bound_upper, result, config_hash | signals, weights, weight_sum                                   |
| 0x03    | Pattern        | anti_structuring  | analysis_type, result, reporting_threshold, time_window, tx_set_hash                   | amounts, timestamps, num_transactions                          |
| 0x04    | Attestation    | tier_verification | provider_id, credential_type, is_valid, merkle_root, current_timestamp                 | credential_hash, subject, attribute, expiry, merkle_proof      |
| 0x05    | Membership     | membership        | merkle_root, set_id, timestamp, is_member                                              | element, merkle_index, merkle_path                             |
| 0x06    | Non-membership | non_membership    | merkle_root, set_id, timestamp, is_non_member                                          | element, low_leaf, high_leaf, low/high indices, low/high paths |

### Verifier Interface

The verifier routes proof verification to per-proof-type verification contracts. Each circuit produces a separate verifier via the ZK backend (e.g., `bb write_solidity_verifier` for Barretenberg's UltraHonk).

```solidity
interface IXochiZKPVerifier {
    /// @notice Verify a zero-knowledge compliance proof
    /// @param proofType The type of proof (0x01-0x06)
    /// @param proof The encoded proof data
    /// @param publicInputs The public inputs to the verification circuit (packed bytes32 values)
    /// @return valid Whether the proof is valid
    function verifyProof(
        uint8 proofType,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Verify a batch of proofs atomically
    /// @param proofTypes Array of proof types
    /// @param proofs Array of encoded proofs
    /// @param publicInputs Array of public input sets
    /// @return valid Whether ALL proofs are valid
    function verifyProofBatch(
        uint8[] calldata proofTypes,
        bytes[] calldata proofs,
        bytes[] calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Get the address of the verifier contract for a proof type
    /// @param proofType The proof type (0x01-0x06)
    /// @return verifier The verifier contract address (address(0) if not set)
    function getVerifier(uint8 proofType) external view returns (address verifier);
}
```

### Oracle Interface

```solidity
interface IXochiZKPOracle {
    struct ComplianceAttestation {
        address subject;
        uint8 jurisdictionId;
        bool meetsThreshold;
        uint256 timestamp;
        uint256 expiresAt;
        bytes32 proofHash;
        bytes32 providerSetHash;
        bytes32 publicInputsHash;
        address verifierUsed;     // verifier contract address at submission time
    }

    event ComplianceVerified(
        address indexed subject,
        uint8 indexed jurisdictionId,
        bool meetsThreshold,
        bytes32 proofHash,
        uint256 expiresAt
    );

    event ProviderWeightsUpdated(
        bytes32 indexed configHash,
        uint256 timestamp,
        string metadataURI
    );

    event AttestationTTLUpdated(uint256 oldTTL, uint256 newTTL);
    event ConfigRevoked(bytes32 indexed configHash);
    event MerkleRootRegistered(bytes32 indexed merkleRoot);
    event MerkleRootRevoked(bytes32 indexed merkleRoot);
    event ReportingThresholdRegistered(bytes32 indexed threshold);
    event ReportingThresholdRevoked(bytes32 indexed threshold);

    /// @notice Submit a compliance proof and record the attestation
    /// @param jurisdictionId Target jurisdiction (0=EU, 1=US, 2=UK, 3=SG)
    /// @param proofType The proof type for verifier routing (0x01-0x06)
    /// @param proof The ZK proof data
    /// @param publicInputs Public inputs matching the circuit's pub parameters
    /// @param providerSetHash Hash of provider IDs and weights used for screening
    /// @return attestation The recorded compliance attestation
    function submitCompliance(
        uint8 jurisdictionId,
        uint8 proofType,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 providerSetHash
    ) external returns (ComplianceAttestation memory attestation);

    /// @notice Check if an address has a valid (non-expired) compliance attestation
    /// @param subject The address to check
    /// @param jurisdictionId The jurisdiction to check against
    /// @return valid Whether a valid, non-expired attestation exists
    /// @return attestation The attestation if valid
    function checkCompliance(
        address subject,
        uint8 jurisdictionId
    ) external view returns (bool valid, ComplianceAttestation memory attestation);

    /// @notice Retrieve a proof for retroactive verification (proof-of-innocence)
    /// @param proofHash The hash of the original compliance proof
    /// @return attestation The original attestation record
    function getHistoricalProof(
        bytes32 proofHash
    ) external view returns (ComplianceAttestation memory attestation);

    /// @notice Get all attestation hashes for a subject in a jurisdiction
    /// @param subject The address to query
    /// @param jurisdictionId The jurisdiction
    /// @return proofHashes Array of proof hashes for historical lookup
    function getAttestationHistory(
        address subject,
        uint8 jurisdictionId
    ) external view returns (bytes32[] memory proofHashes);

    /// @notice Get the current provider weight configuration hash
    /// @return configHash Hash of current provider weights
    function providerConfigHash() external view returns (bytes32 configHash);

    /// @notice Get the current attestation time-to-live
    /// @return ttl Duration in seconds that attestations remain valid
    function attestationTTL() external view returns (uint256 ttl);
}
```

### Jurisdiction Configuration

Implementations MUST publish jurisdiction thresholds openly. Risk scores are expressed in basis points (0-10000 = 0.00%-100.00%).

| ID  | Jurisdiction | Low (bps) | Medium (bps) | High / Filing trigger (bps) |
| --- | ------------ | --------- | ------------ | --------------------------- |
| 0   | EU (AMLD6)   | 0-3099    | 3100-7099    | >=7100                      |
| 1   | US (BSA)     | 0-2599    | 2600-6599    | >=6600                      |
| 2   | UK (MLR)     | 0-3099    | 3100-7099    | >=7100                      |
| 3   | Singapore    | 0-3599    | 3600-7599    | >=7600                      |

### Attestation Lifecycle

Compliance attestations have a configurable time-to-live (TTL):

- Default TTL: 24 hours
- Minimum TTL: 1 hour
- Maximum TTL: 30 days
- `expiresAt = block.timestamp + attestationTTL` at submission time

`checkCompliance()` MUST return `false` for expired attestations. Expired attestations MUST remain retrievable via `getHistoricalProof()` for proof-of-innocence purposes. The TTL is updatable by the oracle administrator via `updateAttestationTTL()`.

### Provider Weight Publication

Implementations SHOULD publish provider weights as an on-chain configuration hash. Weight changes MUST emit `ProviderWeightsUpdated` with the new configuration hash, timestamp, and an optional `metadataURI` pointing to the full configuration (e.g., on IPFS or Arweave).

Provider configuration MUST be versioned. Implementations SHOULD maintain a history of configuration hashes to support retroactive verification: determining which weights were active when a particular proof was generated. Implementations SHOULD support revoking historical configuration hashes when a configuration is discovered to be flawed. The currently active configuration MUST NOT be revocable.

### Proof Type Routing

Implementations MUST maintain a registry mapping each proof type to a per-circuit verifier contract. Each ZK circuit (compiled separately) produces its own verification key and verifier contract. The main verifier contract acts as a router:

1. Caller specifies `proofType` (0x01-0x06)
2. Router looks up the registered verifier for that type
3. Public inputs are decoded from packed `bytes` to `bytes32[]`
4. The per-circuit verifier's `verify(bytes, bytes32[])` is called

Verifier addresses are updatable to allow circuit upgrades. Implementations SHOULD use a two-step ownership transfer pattern for administrative operations.

### Public Input Validation

Implementations MUST validate public inputs semantically for each proof type before forwarding to the per-circuit verifier. The ZK proof guarantees internal consistency (e.g., that the score was correctly computed from the committed inputs), but the oracle MUST verify that those committed inputs match the expected context (e.g., that the config hash is a known configuration, that the merkle root belongs to a registered set). Without this validation, a valid proof generated for one context can be replayed in a different context.

Public inputs MUST be 32-byte aligned. Implementations MUST reject `publicInputs` where `length % 32 != 0`.

The following validation MUST be performed per proof type:

| Proof Type     | Validated Fields                                | Registry                     |
| -------------- | ----------------------------------------------- | ---------------------------- |
| COMPLIANCE     | jurisdiction_id, provider_set_hash, config_hash | Config hash registry         |
| RISK_SCORE     | config_hash                                     | Config hash registry         |
| PATTERN        | reporting_threshold, tx_set_hash != 0           | Reporting threshold registry |
| ATTESTATION    | merkle_root                                     | Merkle root registry         |
| MEMBERSHIP     | merkle_root                                     | Merkle root registry         |
| NON_MEMBERSHIP | merkle_root                                     | Merkle root registry         |

### Validation Registries

Implementations MUST maintain on-chain registries for values that public inputs are validated against. These registries prevent context-spoofing attacks where a proof generated for one context is submitted in a different context.

**Config hash registry.** Tracks valid provider weight configuration hashes. New hashes are added when the administrator updates the configuration. Historical hashes SHOULD be revocable (see Provider Weight Publication). The currently active configuration MUST NOT be revocable.

**Merkle root registry.** Tracks valid merkle roots for MEMBERSHIP, NON_MEMBERSHIP, and ATTESTATION proofs. Roots MUST be registered by the administrator before proofs referencing them can be accepted. Roots SHOULD be revocable when the underlying set is superseded or compromised.

**Reporting threshold registry.** Tracks valid reporting thresholds for PATTERN (anti-structuring) proofs. Each jurisdiction defines its own reporting threshold (e.g., $10,000 for US BSA). Thresholds MUST be registered before proofs referencing them can be accepted.

### Risk Score Computation

The risk score formula MUST be deterministic and publicly verifiable:

$$\text{RiskScore}_{\text{bps}} = \frac{\displaystyle\sum_{i=1}^{N} \text{signal}_i \cdot \text{weight}_i}{W} \times 100$$

where $\text{signal}_i \in [0, 100]$ are provider screening results, $\text{weight}_i$ are published provider weights, $W = \sum_{i=1}^{N} \text{weight}_i$ is the weight sum, and $N \leq 8$ is the number of active providers. The result is in basis points ($0$-$10000$, i.e., $0.00\%$-$100.00\%$).

Circuits that accept `weight_sum` as a private input MUST constrain it to equal the actual sum of the `weights` array. Without this constraint, a malicious prover could pass an arbitrary denominator to inflate or deflate the computed score.

The ZK proof commits to:

- Signal values (hidden)
- Weights used (public via config_hash, must match published config)
- Resulting score (hidden)
- Whether jurisdiction threshold was crossed (revealed as boolean)

### Hash Function Requirements

Circuits MUST use a collision-resistant hash function for all commitments (provider set hashes, config hashes, Merkle trees, credential hashes). The reference implementation uses Pedersen hash, which is efficient in ZK circuits and available in the Noir standard library.

Pedersen commitments are additively homomorphic over the underlying elliptic curve. This is safe provided:

1. Hash outputs are used only as opaque commitments compared via equality.
2. No circuit composes hash outputs arithmetically (e.g., `H(x) + H(y)`).
3. All hash calls use fixed-arity inputs to prevent length-extension reinterpretation.

Implementations MAY migrate to Poseidon2 when high-level APIs stabilize in the circuit language, as Poseidon2 provides stronger random-oracle properties.

### Non-Membership Proof Security

The non-membership circuit proves that an element $e$ is NOT in a sorted Merkle tree by demonstrating adjacency: there exist two consecutive leaves $l$ and $h$ in the tree such that $l < e < h$.

Because Noir Field elements are ~254 bits but the comparison operates on u64, circuits MUST range-check all three values (`element`, `low_leaf`, `high_leaf`) to fit within u64 before casting. Without this check, a ~254-bit Field value could wrap when truncated to u64, producing a false non-membership proof.

### Retroactive Flagging

Each compliance proof MUST commit to:

1. Provider IDs used for screening (committed via providerSetHash)
2. Results returned by each provider at proof time (hidden)
3. The oracle's clearing decision (revealed as meetsThreshold boolean)
4. A timestamp binding the proof to a specific block

This enables proof-of-innocence: counterparties to retroactively flagged addresses can present the original attestation (retrieved via `getHistoricalProof()`) demonstrating the address was clean at transaction time. The on-chain record is immutable and independently verifiable.

## Rationale

**Why client-side computation?** Server-side or TEE-based compliance creates a trusted party that can be coerced, compromised, or surveilled. Client-side ZK proof generation means the raw data never leaves the user's device. The verifier learns only the boolean result.

**Why published weights?** "Black box" compliance algorithms invite regulatory skepticism and legal challenge. Publishing weights and thresholds makes the system auditable without compromising individual privacy. When enforcement data reveals a provider consistently misses bad actors, the weight adjustment is transparent.

**Why on-chain attestations?** Off-chain attestations can be forged, lost, or denied. On-chain records are immutable, timestamped, and independently verifiable. This is critical for proof-of-innocence: the proof must be retrievable months or years after the original transaction.

**Why not Privacy Pools inclusion/exclusion proofs?** Privacy Pools prove set membership ("I'm not in the OFAC set"). This ERC proves compliance with specific rules ("my risk score under jurisdiction X is below threshold Y using providers A, B, C"). Set membership is a subset of what's needed for regulatory compliance.

**Why attestation TTL?** Compliance status is not permanent. A user who was compliant yesterday may not be compliant today. Screening providers update their data continuously. The TTL forces periodic re-attestation while keeping the window configurable per deployment context.

**Why six proof types?** Each proof type maps to a separate ZK circuit with distinct constraint logic. Compliance handles the core risk score check. Risk Score provides standalone threshold/range proofs. Pattern detects structuring behaviors. Attestation verifies credentials from authorized providers. Membership proves inclusion in an authorized set (whitelist). Non-membership proves exclusion from a sanctions list via sorted Merkle tree adjacency. This separation keeps individual circuits small and auditable.

## Backwards Compatibility

This ERC introduces new interfaces and does not modify existing standards. It is designed to complement ERC-5564 (stealth addresses) and ERC-6538 (stealth meta-address registry) for privacy-preserving settlement, but does not depend on them.

## Security Considerations

**Proof soundness.** The security of the system depends on the ZK proof system used. Implementations MUST use a proof system with at least 128-bit security. Groth16, PLONK, and UltraHonk (Noir/Aztec) are acceptable.

**Provider collusion.** If all screening providers collude, they could issue false clean signals. Implementations SHOULD require attestations from multiple independent providers and weight them based on enforcement track record.

**Timestamp manipulation.** Proofs commit to block timestamps. Validators could manipulate timestamps by ~15 seconds on Ethereum. This is acceptable for compliance windows measured in days.

**Regulatory acceptance.** This standard provides a technical mechanism for ZK compliance. Whether specific jurisdictions accept ZK proofs as sufficient compliance evidence is a legal question, not a technical one. The VARA (Dubai) definition of "anonymity-enhanced crypto" excludes assets with "mitigating technologies" for traceability. This standard provides exactly that technology.

**Front-running the oracle.** Compliance proofs are generated before settlement. An adversary who observes a proof submission could infer a trade is about to occur. Implementations SHOULD batch proof submissions or submit them as part of the settlement transaction to minimize information leakage.

**Administrative operations.** Verifier contract updates and provider weight changes are privileged operations. Implementations SHOULD use a two-step ownership transfer pattern (transferOwnership + acceptOwnership) to prevent accidental transfer to an incorrect address. Critical operations (verifier replacement, TTL changes) SHOULD be timelocked in production deployments.

**Public input validation.** Implementations MUST validate public inputs for every proof type, not just the primary compliance proof. Without validation, a prover can generate a proof for one context (e.g., a lenient jurisdiction's reporting threshold) and submit it for a different context. Specifically:

- COMPLIANCE and RISK_SCORE proofs MUST validate `config_hash` against a registry of known configurations.
- COMPLIANCE proofs MUST validate `jurisdiction_id` and `provider_set_hash` against caller-supplied parameters.
- PATTERN (anti-structuring) proofs MUST validate `reporting_threshold` against a per-jurisdiction registry.
- MEMBERSHIP, NON_MEMBERSHIP, and ATTESTATION proofs MUST validate `merkle_root` against a registry of known roots.

**Proof replay prevention.** Proof hashes MUST be keyed on both the proof bytes and the proof type: `keccak256(abi.encodePacked(proof, proofType))`. Keying on proof bytes alone would prevent the same bytes from being submitted for a different proof type, which is an unnecessary restriction.

**Config and root revocation.** Provider configuration hashes and merkle roots SHOULD be revocable. Without revocation, a discovered-to-be-flawed configuration or a compromised merkle tree remains accepted forever. Implementations MUST NOT allow revoking the currently active provider configuration.

**Verifier TOCTOU.** Implementations MUST resolve the verifier address once per submission and use it for both proof verification and attestation recording. A time-of-check/time-of-use gap between address resolution and proof verification could allow the recorded `verifierUsed` to diverge from the actual verifier if a verifier upgrade occurs mid-transaction.

## Reference Implementation

A reference implementation is provided at [erc-xochi-zkp](https://github.com/xochi-fi/erc-xochi-zkp):

- **Solidity contracts**: `src/XochiZKPVerifier.sol`, `src/XochiZKPOracle.sol` (Foundry, Solidity 0.8.28)
- **Noir circuits**: `circuits/` (one per proof type, compiled with nargo 1.0)
- **Generated verifiers**: `src/generated/` (UltraHonk verifiers generated by Barretenberg)
- **Test suite**: 109 Solidity tests (unit, fuzz, invariant, integration with real proofs), 36 circuit tests

## Test Vectors

The reference implementation includes binary proof fixtures in `test/fixtures/` for end-to-end verification. Each fixture contains:

- `proof`: the raw UltraHonk proof bytes
- `public_inputs`: the packed bytes32 public inputs

The compliance fixture uses the following witness:

- Single provider (id=1, weight=100), signal=20 (low risk)
- Jurisdiction: EU (id=0), threshold: 7100 bps
- Computed score: 2000 bps (below threshold, meets_threshold=true)
- config_hash: `0x18574f427f33c6c77af53be06544bd749c9a1db855599d950af61ea613df8405` (pedersen_hash of weight config)

Fixtures can be regenerated via `scripts/generate-fixtures.sh`.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
