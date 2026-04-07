# TODO

## Current Status

- 109/109 Solidity tests pass (forge test)
- 36/36 Noir circuit tests pass (nargo test, 7 projects)
- EIP draft aligned with implementation
- Tooling: nargo 1.0.0-beta.19, forge 1.5.1, bb 4.0.0-nightly.20260120
- Gas snapshot captured (.gas-snapshot)
- Real proof fixtures for compliance + risk_score circuits

## Completed Security Fixes

### Circuit fixes
- [x] Non-membership u64 truncation -- range checks enforcing values fit in u64 before comparison
- [x] Risk score overflow -- MAX_WEIGHT (10000) constraint preventing u32 overflow
- [x] Risk score weight_sum validation -- circuit asserts computed_weight_sum == weight_sum
- [x] Provider set hash array size -- assertion enforcing N <= MAX_PROVIDERS
- [x] Zero-value provider ambiguity -- active providers require non-zero IDs
- [x] Anti-structuring floor overflow -- MAX_REPORTING_THRESHOLD guard
- [x] Pedersen security audit -- homomorphic properties documented, no circuit exploits them

### Solidity fixes
- [x] IUltraVerifier view mismatch -- verify() now view, cascaded through all interfaces
- [x] Public input validation for all 6 proof types (was only COMPLIANCE + RISK_SCORE)
- [x] TOCTOU elimination -- verifier address resolved once, used for both verify and record
- [x] Proof hash keyed on (proof, proofType) -- prevents cross-type collisions
- [x] Public input alignment check -- rejects inputs where length % 32 != 0
- [x] Merkle root registry -- MEMBERSHIP/NON_MEMBERSHIP/ATTESTATION validate against registered roots
- [x] Reporting threshold registry -- PATTERN validates against registered thresholds
- [x] Config revocation -- revokeConfig() with CannotRevokeCurrentConfig guard
- [x] Proof replay protection -- _usedProofs mapping, ProofAlreadyUsed error
- [x] Attestation history pagination -- getAttestationHistoryPaginated()
- [x] Ownership transfer timeout -- 48-hour deadline on both contracts

### Tests added
- [x] Proof replay, jurisdiction mismatch, providerSetHash mismatch
- [x] Unaligned public inputs rejection
- [x] Merkle root validation (MEMBERSHIP, NON_MEMBERSHIP, ATTESTATION)
- [x] Reporting threshold validation (PATTERN)
- [x] Cross-type proof replay allowed (different proofType = different hash)
- [x] TTL boundary precision (valid at exact expiry, invalid 1s after)
- [x] Config revocation (blocks submission, revert not owner, cannot revoke current)
- [x] View verifier prevents reentrancy (TOCTOU test)
- [x] Fuzz: expired attestation never valid, replay always reverts, attestation fields consistent
- [x] Fuzz: revoked config blocks submission, all proof types, encoding round trips
- [x] Integration tests with real compliance proofs
- [x] Circuit main() tests for all 6 circuits

### Infrastructure
- [x] generate-fixtures.sh -- compiles, proves, verifies, generates Solidity verifiers
- [x] Real proof fixtures for compliance and risk_score
- [x] Regenerated risk_score verifier from updated circuit

## Short-term

- [ ] Add CI workflow (GitHub Actions: `forge test` + `nargo test`)
- [ ] Add `Makefile` with build/test/lint targets
- [ ] Add pre-commit hooks (forge fmt check)
- [ ] Generate proof fixtures for remaining 4 circuits (anti_structuring, tier_verification, membership, non_membership)
- [ ] Integration tests with real proofs for all 6 proof types

## Medium-term

- [ ] Client SDK (TypeScript): `@noir-lang/noir_js` + `@aztec/bb.js` wrapper
- [ ] Provider signal mock server for local development
- [ ] Gas benchmarks for each proof type verification
- [ ] Formal verification of jurisdiction threshold logic

## Pre-deployment

- [ ] External security audit (Solidity + Noir circuits)
- [ ] Testnet deployment (Sepolia, Base Sepolia)
- [ ] Documentation site
- [ ] EIP submission to ethereum/EIPs
- [ ] Timelock on admin operations (verifier updates, TTL changes)
- [ ] Multi-sig for oracle ownership

## Design decisions (documented, not bugs)

- **meetsThreshold always true**: Failed proofs revert at verifier, so only compliant proofs are recorded. Field kept for checkCompliance() query interface.
- **No access control on submitCompliance()**: Anyone can prove compliance for themselves. Restricting to relayers would add centralization.
- **Proof hash keyed on (proof, proofType)**: Different proof types produce different hashes even for identical proof bytes. Prevents cross-type collision.
- **Jurisdiction thresholds hardcoded**: By design per ERC spec. Updating requires contract upgrade, appropriate for regulatory thresholds.
- **Pedersen vs Poseidon2**: Using Pedersen due to Noir API stability. Homomorphic properties not exploitable in current circuit compositions. Migrate when Poseidon2 stabilizes.
- **TTL boundary inclusive**: checkCompliance uses `<=` for expiresAt. Attestation valid for exactly TTL seconds inclusive.
- **verifier immutable on Oracle**: XochiZKPVerifier address is immutable. Individual per-type verifiers are upgradeable via setVerifier().
