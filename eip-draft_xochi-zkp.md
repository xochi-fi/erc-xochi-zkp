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

- **View keys** (Railgun, Panther): Trade privately, then reveal raw transaction data to auditors on request. This leaks the data -- it's just delayed transparency.
- **TEE-based compliance** (various): Rely on hardware trust assumptions that have been broken repeatedly (SGX side channels, key extraction).
- **Compliance-by-exclusion** (Privacy Pools): Prove you're NOT in a bad set. Doesn't prove you ARE compliant with specific jurisdiction rules.

This ERC defines a standard where compliance is proven cryptographically at transaction time. The proof commits to screening results, jurisdiction thresholds, and provider attestations. Regulators verify a proof. They never see the underlying data.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Proof Types

Implementations MUST support the following proof types:

| Type ID | Name           | Public inputs                   | Private inputs       |
| ------- | -------------- | ------------------------------- | -------------------- |
| 0x01    | Threshold      | direction (gt/lt), threshold    | amount               |
| 0x02    | Range          | lower bound, upper bound        | amount               |
| 0x03    | Membership     | set commitment (Merkle root)    | element, Merkle path |
| 0x04    | Non-membership | set commitment (Merkle root)    | element, Merkle path |
| 0x05    | Pattern        | analysis type, result (boolean) | transaction set      |
| 0x06    | Attestation    | provider ID, validity (boolean) | credential data      |

### Verifier Interface

```solidity
interface IXochiZKPVerifier {
    /// @notice Verify a zero-knowledge compliance proof
    /// @param proofType The type of proof (0x01-0x06)
    /// @param proof The encoded proof data
    /// @param publicInputs The public inputs to the verification circuit
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
        bytes32 proofHash;
        bytes32 providerSetHash;
    }

    event ComplianceVerified(
        address indexed subject,
        uint8 indexed jurisdictionId,
        bool meetsThreshold,
        bytes32 proofHash
    );

    event ProviderWeightsUpdated(
        bytes32 indexed configHash,
        uint256 timestamp
    );

    /// @notice Submit a compliance proof and record the attestation
    /// @param jurisdictionId Target jurisdiction (0=EU, 1=US, 2=UK, 3=SG)
    /// @param proof The ZK proof data
    /// @param publicInputs Public inputs including threshold result
    /// @return attestation The recorded compliance attestation
    function submitCompliance(
        uint8 jurisdictionId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (ComplianceAttestation memory attestation);

    /// @notice Check if an address has a valid compliance attestation
    /// @param subject The address to check
    /// @param jurisdictionId The jurisdiction to check against
    /// @return valid Whether a valid attestation exists
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

    /// @notice Get the current provider weight configuration hash
    /// @return configHash Hash of current provider weights
    function providerConfigHash() external view returns (bytes32 configHash);
}
```

### Jurisdiction Configuration

Implementations MUST publish jurisdiction thresholds openly:

| ID  | Jurisdiction | Low  | Medium | High | Filing trigger |
| --- | ------------ | ---- | ------ | ---- | -------------- |
| 0   | EU (AMLD6)   | 0-30 | 31-70  | >70  | High           |
| 1   | US (BSA)     | 0-25 | 26-65  | >65  | High           |
| 2   | UK (MLR)     | 0-30 | 31-70  | >70  | High           |
| 3   | Singapore    | 0-35 | 36-75  | >75  | High           |

### Provider Weight Publication

Implementations SHOULD publish provider weights as an on-chain configuration hash. Weight changes MUST emit `ProviderWeightsUpdated` with the new configuration hash and timestamp. Historical configurations SHOULD be retrievable for proof-of-innocence verification.

### Risk Score Computation

The risk score formula MUST be deterministic and publicly verifiable:

```
RiskScore = SUM(weight_i * signal_i)
```

Where `weight_i` are published provider weights and `signal_i` are provider screening results. The ZK proof commits to:

- Signal values (hidden)
- Weights used (public, must match published config)
- Resulting score (hidden)
- Whether jurisdiction threshold was crossed (revealed as boolean)

### Retroactive Flagging

Each compliance proof MUST commit to:

1. Provider IDs used for screening (hidden, but deconstructable by enforcement)
2. Results returned by each provider at proof time (hidden)
3. The oracle's clearing decision (revealed)
4. A timestamp binding the proof to a specific block

This enables proof-of-innocence: counterparties to retroactively flagged addresses can present the original proof demonstrating the address was clean at transaction time.

## Rationale

**Why client-side computation?** Server-side or TEE-based compliance creates a trusted party that can be coerced, compromised, or surveilled. Client-side ZK proof generation means the raw data never leaves the user's device. The verifier learns only the boolean result.

**Why published weights?** "Black box" compliance algorithms invite regulatory skepticism and legal challenge. Publishing weights and thresholds makes the system auditable without compromising individual privacy. When enforcement data reveals a provider consistently misses bad actors, the weight adjustment is transparent.

**Why on-chain attestations?** Off-chain attestations can be forged, lost, or denied. On-chain records are immutable, timestamped, and independently verifiable. This is critical for proof-of-innocence: the proof must be retrievable months or years after the original transaction.

**Why not Privacy Pools inclusion/exclusion proofs?** Privacy Pools prove set membership ("I'm not in the OFAC set"). This ERC proves compliance with specific rules ("my risk score under jurisdiction X is below threshold Y using providers A, B, C"). Set membership is a subset of what's needed for regulatory compliance.

## Backwards Compatibility

This ERC introduces new interfaces and does not modify existing standards. It is designed to complement ERC-5564 (stealth addresses) and ERC-6538 (stealth meta-address registry) for privacy-preserving settlement, but does not depend on them.

## Security Considerations

**Proof soundness.** The security of the system depends on the ZK proof system used. Implementations MUST use a proof system with at least 128-bit security. Groth16, PLONK, and UltraPlonk (Noir/Aztec) are acceptable.

**Provider collusion.** If all screening providers collude, they could issue false clean signals. Implementations SHOULD require attestations from multiple independent providers and weight them based on enforcement track record.

**Timestamp manipulation.** Proofs commit to block timestamps. Validators could manipulate timestamps by ~15 seconds on Ethereum. This is acceptable for compliance windows measured in days.

**Regulatory acceptance.** This standard provides a technical mechanism for ZK compliance. Whether specific jurisdictions accept ZK proofs as sufficient compliance evidence is a legal question, not a technical one. The VARA (Dubai) definition of "anonymity-enhanced crypto" excludes assets with "mitigating technologies" for traceability -- this standard provides exactly that technology.

**Front-running the oracle.** Compliance proofs are generated before settlement. An adversary who observes a proof submission could infer a trade is about to occur. Implementations SHOULD batch proof submissions or submit them as part of the settlement transaction to minimize information leakage.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
