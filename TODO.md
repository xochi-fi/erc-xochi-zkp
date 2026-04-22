# TODO

## Current Status

- 229/229 Solidity tests pass (59 verifier + 116 oracle + 41 registry + 5 invariant + 8 ProofTypes; 10 integration tests need fixture regen)
- 70/70 Noir circuit tests pass (7 packages: shared 11, compliance 8, risk_score 13, pattern 12, attestation 10, membership 5, non_membership 11)
- 16/16 xochi e2e tests pass (TS + anvil, all 6 proof types + runtime proving)
- 3/3 TS consumer SDK tests pass (noir_js -> bb.js -> anvil -> on-chain verify)
- 7/7 client SDK tests pass (XochiProver + encoding)
- EIP draft aligned with implementation
- Tooling: nargo 1.0.0-beta.20, forge 1.5.1, bb 4.0.0-nightly.20260120
- Gas snapshot needs update (public input counts changed)
- Real proof fixtures need regen (submitter field added to all 6 circuits)
- xochi integration: shared oracle ABI, worker on-chain verification, useCompliance hook, real ZK proving
- Client SDK: `@xochi/sdk` in ../xochi-sdk (XochiProver, typed input builders, 3 circuit loaders)

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
</details>

<details>
<summary>Test coverage</summary>

- Proof replay, jurisdiction mismatch, providerSetHash mismatch
- Unaligned public inputs rejection
- Merkle root + reporting threshold validation
- Cross-type proof replay allowed (different hash)
- TTL boundary precision, config revocation
- View verifier prevents reentrancy (TOCTOU test)
- Fuzz: expired attestation, replay, attestation fields, revoked config, encoding round trips
- Integration tests with real proofs for all 6 circuits
- Circuit main() tests for all 6 circuits
</details>

<details>
<summary>Infrastructure + integrations</summary>

- generate-fixtures.sh (compile, prove, verify, generate Solidity verifiers)
- Makefile with build/test/lint targets, pre-commit hooks (forge fmt check)
- xochi e2e harness, shared oracle module, worker verification, useCompliance hook
- Runtime proof generation in xochi e2e (replaced fixture-loading)
- TS consumer SDK test, client SDK repo (@xochi/sdk)
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
- [ ] **Run Slither + Mythril static analysis**: No static analysis has been run on the contracts. Slither catches common patterns (reentrancy, unchecked returns, etc.), Mythril finds symbolic execution bugs. Add to CI.

### Medium priority

- [ ] **setVerifier code existence check**: `setVerifier(proofType, addr)` accepts any address, including EOAs or contracts without `verify()`. Add `addr.code.length > 0` check. Consider a dry-run verification call.
- [ ] **Per-proof-type pause**: Currently pause() stops all proof types. A compromised verifier for one type requires pausing the entire system. Add `pauseProofType(uint8)` / `unpauseProofType(uint8)` for surgical response.
- [ ] **Emergency verifier revocation**: If a verifier is compromised, setting a new one still allows the old one to be used via `verifyProofAtVersion`. Add ability to revoke a specific version from the history.
- [ ] **Formal verification of jurisdiction thresholds**: The Noir `get_high_threshold()` and Solidity `JurisdictionConfig.getThresholds()` must match exactly. Currently verified by inspection only. Write a cross-validation test (forge ffi calling nargo to compute thresholds, compare against Solidity).
- [ ] **Config history cleanup**: `MAX_CONFIG_HISTORY = 256` is a hard cap with no cleanup mechanism. After 256 updates, the Oracle is permanently stuck. Add `compactConfigHistory()` that removes revoked entries, or increase the cap.

### Low priority

- [ ] **Attestation history gas griefing**: `_attestationHistory[subject][jurisdiction]` is unbounded. Repeated submissions grow the array, increasing gas for `getAttestationHistory()`. Not exploitable (submitter pays gas) but worth documenting for integrators using `getAttestationHistory` vs paginated variant.
- [ ] **ProofTypes.decodePublicInputs assembly optimization**: The loop decodes 32-byte slots one at a time with calldata slicing. A `calldatacopy` into memory would be cheaper for large input counts.
- [ ] **Add EIP-712 typed data hashing**: For off-chain attestation verification, typed hashing would let wallets display structured data instead of raw bytes.

## Low-priority test gaps

- [ ] SDK `.todo()` tests for pattern + attestation circuits (blocked on circuit builds in CI)
- [ ] Exhaustive cross-type proof routing rejection (all 30 mismatch permutations)
- [ ] Fuzz jurisdiction ID permutations in submitCompliance (4 values, unit tests sufficient)
- [ ] Fuzz metadata URI strings in updateProviderConfig (long strings, special chars)
- [ ] Fuzz corrupted proof bytes (various corruption patterns beyond single-byte flip)
- [ ] Test paginated history with limit=0, fuzz arbitrary offset/limit combinations
- [ ] Test that old proofs with revoked config are still retrievable via getHistoricalProof
- [ ] Non-membership: value at exact MAX_ELEMENT_VALUE boundary (2^64-1)
- [ ] Compliance: multi-provider score that lands exactly 1 bps below threshold
- [ ] Pattern: threshold=MAX_REPORTING_THRESHOLD boundary, num_transactions=1 edge case

## Next up

### 1. CI workflow (GitHub Actions)

Two jobs: `solidity` and `circuits`. Both trigger on push/PR to main.

**solidity job:**

- Install foundry (foundry-rs/foundry-toolchain action)
- `forge build --sizes` (catch contract size regressions)
- `forge test -vvv`
- `forge fmt --check`
- Cache: `~/.config/.foundry`

**circuits job:**

- Install nargo via noirup (noir-lang/noirup action or curl)
- `cd circuits && nargo test --workspace`
- Cache: `~/.nargo`

Optional: add `sdk` job later when CI has node/npm (low priority, fast locally).

### 2. Testnet deployment (Sepolia + Base Sepolia)

Prerequisite: CI green.

- [ ] Deploy script updates: chain-specific config (RPC URLs, gas settings)
- [ ] Deploy generated verifiers (6 contracts per chain)
- [ ] Deploy XochiZKPVerifier, register all 6 per-type verifiers
- [ ] Deploy XochiZKPOracle with initial config hash
- [ ] Register initial merkle roots + reporting thresholds
- [ ] Verify all contracts on Etherscan/Basescan
- [ ] Smoke test: submit a real compliance proof on testnet
- [ ] Document deployed addresses in README

### 3. Timelock + multi-sig for admin ops

Prerequisite: testnet deployment validated.

- [ ] TimelockController for admin operations (verifier updates, TTL changes, config updates)
- [ ] Minimum delay: 24h for verifier updates, 6h for TTL/config
- [ ] Safe multi-sig as timelock proposer (2-of-3 minimum)
- [ ] Update Oracle + Verifier ownership to timelock
- [ ] Test timelock flow end-to-end on testnet

### 4. Gas benchmarks

- [ ] Per-proof-type verification gas (all 6 types, real proofs)
- [ ] submitCompliance gas breakdown (verify + storage + events)
- [ ] Batch verification gas scaling curve
- [ ] Add to CI as regression check (forge snapshot --check)

### 5. Documentation site

- [ ] EIP spec as primary reference
- [ ] Integration guide (SDK usage, proof generation, on-chain verification)
- [ ] Circuit architecture diagrams
- [ ] Deployment guide (testnet + mainnet)
- [ ] Threat model + security considerations

## Pre-deployment (blocked on testnet validation)

- [ ] External security audit (Solidity + Noir circuits)
- [ ] EIP submission to ethereum/EIPs
- [ ] Provider signal mock server for local development
- [ ] Formal verification of jurisdiction threshold logic

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
