# TODO

## Current Status

- 327/327 Solidity tests pass (72 verifier + 131 oracle + 41 registry + 5 invariant + 8 ProofTypes + 16 integration + 22 timelock + 16 gas benchmark + 6 ProofTypes fuzz + 5 EIP712 + 5 threshold cross-validation)
- 77/77 Noir circuit tests pass (7 packages: shared 12, compliance 10, risk_score 13, pattern 14, attestation 10, membership 5, non_membership 13)
- 16/16 xochi e2e tests pass (TS + anvil, all 6 proof types + runtime proving)
- 28/35 TS consumer SDK tests pass (7 todo; noir_js + bb.js + anvil + on-chain verify)
- 7/7 client SDK tests pass (XochiProver + encoding)
- EIP draft aligned with implementation
- Tooling: nargo 1.0.0-beta.20, forge 1.5.1, bb 4.0.0-nightly.20260120
- CI green (solidity + circuits + sdk jobs)
- Gas benchmarks: ~2.43M verify, ~2.85M submit, linear batch scaling
- Client SDK: `@xochi/sdk@^0.1.1` (published on npm)

## Completed

<details>
<summary>Security fixes (circuits + Solidity)</summary>

- Non-membership u64 truncation range checks
- Risk score overflow (MAX_WEIGHT constraint), weight_sum validation
- Provider set hash array size assertion, zero-value provider ambiguity guard
- Pattern floor overflow (MAX_REPORTING_THRESHOLD guard)
- Pedersen homomorphic properties documented (no circuit exploits them)
- IUltraVerifier view mismatch fixed (verify() now view)
- Public input validation for all 6 proof types
- TOCTOU elimination (verifier address resolved once)
- Proof hash keyed on (proof, proofType) for cross-type collision prevention
- Public input alignment check (rejects length % 32 != 0)
- Merkle root registry for MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION
- Reporting threshold registry for PATTERN
- Config revocation with CannotRevokeCurrentConfig guard
- Proof replay protection (\_usedProofs mapping)
- Attestation history pagination
- Ownership transfer 48-hour timeout on both contracts
</details>

<details>
<summary>Security hardening (2026-04-22)</summary>

- Proof front-running mitigation: submitter pub Field added to all 6 circuits, Oracle enforces submitter == msg.sender
- Circuit timestamp staleness check: MAX_PROOF_AGE (1 hour) enforced for COMPLIANCE, ATTESTATION, MEMBERSHIP, NON_MEMBERSHIP
- Mandatory timelock on verifier replacement: 24h propose/execute/cancel pattern, setVerifierInitial for deployment only
- Pattern time_window minimum: MIN_TIME_WINDOW (3600s) enforced in Oracle
- proofType in ComplianceAttestation: struct field + checkComplianceByType() query
- Noir u1 -> bool migration (nargo 1.0.0-beta.20 compat)
- Verifier code existence check: setVerifierInitial/proposeVerifier reject EOAs (NotAContract error)
- Per-proof-type pause: pauseProofType/unpauseProofType on both Verifier and Oracle
- Emergency verifier revocation: revokeVerifierVersion blocks compromised versions
</details>

<details>
<summary>Security hardening (2026-04-25)</summary>

- Slither static analysis: 36 findings triaged, all false positives or by-design. Config in slither.config.json, CI job added.
- Mythril symbolic execution: 0 issues on Oracle, Verifier, SettlementRegistry, Timelock
- Config history cleanup: compactConfigHistory() removes revoked entries, frees slots for new configs
- EIP-712 typed data hashing: EIP712Attestation library for off-chain attestation verification
- ProofTypes.decodePublicInputs: calldatacopy assembly optimization (~60 gas/input saved)
- Jurisdiction threshold cross-validation: paired Noir + Solidity tests assert identical values
- Attestation history gas griefing: documented in NatSpec, integrators directed to paginated variant
- Circuit edge-case tests: non-membership u64 max boundary, compliance 1-bps-below-threshold, pattern MAX_REPORTING_THRESHOLD
</details>

<details>
<summary>Infrastructure + integrations</summary>

- generate-fixtures.sh (compile, prove, verify, generate Solidity verifiers)
- Makefile with build/test/lint/benchmark targets, pre-commit hooks (forge fmt check)
- xochi e2e harness, shared oracle module, worker verification, useCompliance hook
- Runtime proof generation in xochi e2e (replaced fixture-loading)
- TS consumer SDK test, client SDK repo (@xochi/sdk)
- CI workflow (GitHub Actions): solidity + circuits + sdk jobs, nargo 1.0.0-beta.20
- XochiTimelock: 2-tier delay (24h verifier, 6h config), proposer/guardian roles
- Gas benchmarks: per-proof-type verify/submit, batch scaling curve, CI regression check
</details>

<details>
<summary>Code quality refactor (2026-04-08)</summary>

- Extracted shared Noir utilities: verify_weight_sum, weights_to_fields, compute_config_hash, validate_timestamp, compute_tx_set_hash
- Created circuits/shared/src/validation.nr module
- Refactored 5 circuits to use shared functions (~60 lines deduplication)
- Expanded comments: Merkle bit encoding, two-round hashing rationale, truncation attack explanation
- Extracted Solidity Ownable2Step + Pausable abstract contracts (~50 lines deduplication)
- Refactored Oracle + Verifier to inherit shared base contracts
</details>

## Security hardening

### High priority (pre-mainnet blockers)

- [x] **Proof front-running mitigation**: All 6 circuits expose `submitter: pub Field`. Oracle enforces `submitter == msg.sender` via `SubmitterMismatch` error.
- [x] **Circuit timestamp staleness check**: `MAX_PROOF_AGE = 1 hour` enforced for COMPLIANCE, ATTESTATION, MEMBERSHIP, NON_MEMBERSHIP. RISK_SCORE and PATTERN have no timestamp (documented).
- [x] **Mandatory timelock on verifier replacement**: `proposeVerifier()` + `executeVerifierUpdate()` with 24h `VERIFIER_TIMELOCK`. `setVerifierInitial()` for first-time setup only. `cancelVerifierProposal()` + `getPendingVerifier()` for management.
- [x] **Pattern time_window minimum enforcement**: `MIN_TIME_WINDOW = 3600` (1 hour) enforced in `_validatePatternInputs()`. `TimeWindowTooSmall` error.
- [x] **Cross-type attestation semantic gap**: `uint8 proofType` added to `ComplianceAttestation` struct. `checkComplianceByType()` filters by proof type. `getProofType()` still available via mapping.
- [x] **Run Slither + Mythril static analysis**: Slither v0.11.5 -- 36 findings, all triaged as false positives or by-design patterns (timelock arbitrary-send-eth, sentinel value strict equality, timestamp comparisons). Config in `slither.config.json`, CI job added. Mythril symbolic execution -- 0 issues on all 4 contracts (Oracle, Verifier, SettlementRegistry, Timelock). Generated UltraHonk verifiers excluded (crash Slither's constant-folding parser, separately audited by Aztec).

### Medium priority

- [x] **Verifier code existence check**: `setVerifierInitial` and `proposeVerifier` reject EOAs via `addr.code.length > 0` (`NotAContract` error).
- [x] **Per-proof-type pause**: `pauseProofType(uint8)` / `unpauseProofType(uint8)` on both Verifier and Oracle. Surgical response without stopping the entire system.
- [x] **Emergency verifier revocation**: `revokeVerifierVersion(proofType, version)` blocks compromised versions from `verifyProofAtVersion`. Cannot revoke current version. No timelock (emergency action).
- [x] **Formal verification of jurisdiction thresholds**: Paired cross-validation tests in Solidity (`test/ThresholdCrossValidation.t.sol`) and Noir (`circuits/shared/src/risk.nr:test_threshold_cross_validation_all`). Both assert identical threshold values with cross-references to the other file.
- [x] **Config history cleanup**: `compactConfigHistory()` removes revoked entries in-place, preserving ordering. Current config always survives (CannotRevokeCurrentConfig guard). Emits `ConfigHistoryCompacted` event. 4 tests cover removal, no-op, access control, and post-compaction updates.

### Low priority

- [x] **Attestation history gas griefing**: Documented in NatSpec on `getAttestationHistory()` (Oracle + interface). Unbounded array is not exploitable (submitter pays gas) but can exceed RPC limits. Integrators directed to `getAttestationHistoryPaginated()`.
- [x] **ProofTypes.decodePublicInputs assembly optimization**: Replaced per-slot calldata slicing loop with single `calldatacopy` instruction. Saves ~60 gas per additional public input. Existing fuzz tests validate correctness.
- [x] **Add EIP-712 typed data hashing**: `EIP712Attestation` library with domain separator, struct hash, and full digest. Oracle exposes `DOMAIN_SEPARATOR()` and `hashAttestation()` convenience views. Fork-safe (uses `block.chainid` at call time). 5 tests.

## Low-priority test gaps

- [ ] SDK `.todo()` tests for pattern + attestation circuits (blocked on circuit builds in CI)
- [ ] Exhaustive cross-type proof routing rejection (all 30 mismatch permutations)
- [x] Fuzz jurisdiction ID permutations in submitCompliance (all 4 valid values, 256 runs)
- [x] Fuzz metadata URI strings in updateProviderConfig (0-1024 chars, arbitrary bytes)
- [x] Fuzz corrupted proof bytes (random offset + byte corruption with AlwaysFailVerifier)
- [x] Test paginated history with limit=0, fuzz arbitrary offset/limit combinations (0-20 range)
- [x] Test that old proofs with revoked config are still retrievable via getHistoricalProof
- [x] Non-membership: value at exact MAX_ELEMENT_VALUE boundary (2^64-1)
- [x] Compliance: multi-provider score that lands exactly 1 bps below threshold (EU + US)
- [x] Pattern: threshold=MAX_REPORTING_THRESHOLD boundary, num_transactions=1 edge case (clean + suspicious)

## Next up

### 1. Testnet deployment (Sepolia + Base Sepolia)

Prerequisite: CI green.

- [ ] Deploy script updates: chain-specific config (RPC URLs, gas settings)
- [ ] Deploy generated verifiers (6 contracts per chain)
- [ ] Deploy XochiZKPVerifier, register all 6 per-type verifiers
- [ ] Deploy XochiZKPOracle with initial config hash
- [ ] Deploy XochiTimelock with Safe multi-sig as proposer
- [ ] Transfer Verifier + Oracle ownership to timelock
- [ ] Register initial merkle roots + reporting thresholds
- [ ] Verify all contracts on Etherscan/Basescan
- [ ] Smoke test: submit a real compliance proof on testnet
- [ ] Document deployed addresses in README

### 2. Documentation site

- [ ] EIP spec as primary reference
- [ ] Integration guide (SDK usage, proof generation, on-chain verification)
- [ ] Circuit architecture diagrams
- [ ] Deployment guide (testnet + mainnet)
- [ ] Threat model + security considerations

## Pre-deployment (blocked on testnet validation)

- [ ] External security audit (Solidity + Noir circuits)
- [ ] EIP submission to ethereum/EIPs
- [ ] Provider signal mock server for local development
- [x] Formal verification of jurisdiction threshold logic

## Gas benchmarks

| Operation              | Gas    | Notes                                    |
| ---------------------- | ------ | ---------------------------------------- |
| verifyProof (any type) | ~2.43M | UltraHonk verification dominates         |
| submitCompliance       | ~2.85M | +380K Oracle overhead (storage + events) |
| batch verify x1        | 2.86M  | Baseline                                 |
| batch verify x2        | 4.84M  | ~2.42M/proof                             |
| batch verify x5        | 12.07M | ~2.41M/proof                             |
| batch verify x10       | 24.12M | ~2.41M/proof (linear)                    |

## Design decisions (documented, not bugs)

- **meetsThreshold always true**: Failed proofs revert at verifier, so only compliant proofs are recorded. Field kept for checkCompliance() query interface.
- **No access control on submitCompliance()**: Anyone can prove compliance for themselves. Restricting to relayers would add centralization.
- **Proof hash keyed on (proof, proofType)**: Different proof types produce different hashes even for identical proof bytes. Prevents cross-type collision.
- **Jurisdiction thresholds hardcoded**: By design per ERC spec. Updating requires contract upgrade, appropriate for regulatory thresholds.
- **Pedersen vs Poseidon2**: Using Pedersen due to Noir API stability. Homomorphic properties not exploitable in current circuit compositions. Migrate when Poseidon2 stabilizes.
- **TTL boundary inclusive**: checkCompliance uses `<=` for expiresAt. Attestation valid for exactly TTL seconds inclusive.
- **verifier immutable on Oracle**: XochiZKPVerifier address is immutable. Individual per-type verifiers are upgradeable via setVerifier().
- **Circuit names match ProofTypes**: Circuit directories (pattern, attestation) match Solidity ProofTypes constants 1:1. Previously `anti_structuring` and `tier_verification`, renamed for ontology alignment.
- **compliance vs risk_score**: Both use `compute_risk_score()` from shared. Compliance is the primary jurisdiction-aware proof. Risk score is a raw scoring primitive for custom integrations (GT/LT/range, no jurisdiction). Intentional composition, not duplication.
- **Double timelock for verifier updates**: External XochiTimelock (24h) + internal verifier timelock (24h) = 48h total. Defense-in-depth: even if the timelock controller is compromised, the verifier's internal timelock provides a second layer. Emergency bypass via `revokeVerifierVersion` and `pauseProofType` (no timelock).
