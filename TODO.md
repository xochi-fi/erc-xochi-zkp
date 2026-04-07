# TODO

## Current Status

- 63/63 Solidity tests pass (forge test) -- up from 43
- 43/43 Noir circuit tests pass (nargo test, 7 projects) -- up from 27
- EIP draft aligned with implementation
- Tooling: nargo 1.0.0-beta.19, forge 1.5.1, bb 0.72.1 (incompatible)
- via_ir removed from foundry.toml (no longer needed)

## Completed Security Fixes

### Circuit fixes
- [x] Non-membership u64 truncation -- added range checks enforcing all values fit in u64 before comparison
- [x] Risk score overflow -- added MAX_WEIGHT (10000) constraint preventing u32 overflow in weighted sum
- [x] Provider set hash array size -- added assertion enforcing N <= MAX_PROVIDERS in compute_provider_set_hash
- [x] Zero-value provider ambiguity -- active providers now require non-zero IDs; inactive slots must be fully zeroed
- [x] Anti-structuring floor overflow -- added MAX_REPORTING_THRESHOLD guard preventing u64 overflow in floor calc
- [x] Pedersen security audit -- documented homomorphic properties, confirmed no circuit exploits them

### Solidity fixes
- [x] Proof replay protection -- added _usedProofs mapping, ProofAlreadyUsed error
- [x] meetsThreshold always-true -- documented as intentional (failed proofs revert at verifier)
- [x] proofType-publicInputs semantic validation -- _validateComplianceInputs checks jurisdiction and providerSetHash match public inputs
- [x] providerSetHash verified against public inputs -- extracted from proof's public inputs, no longer caller-trusted
- [x] Attestation history pagination -- added getAttestationHistoryPaginated(subject, jurisdiction, offset, limit)
- [x] Ownership transfer timeout -- 48-hour deadline on both Verifier and Oracle pendingOwner
- [x] via_ir removed -- contracts compile without IR pipeline (was not actually needed)

### Tests added
- [x] Proof replay rejection test
- [x] Jurisdiction mismatch / providerSetHash mismatch tests
- [x] Paginated history test
- [x] Concurrent multi-jurisdiction attestation tests
- [x] Independent expiry per jurisdiction test
- [x] Ownership transfer expiry + re-initiation tests
- [x] Non-compliance proof type bypasses input validation test
- [x] Fuzz: TTL valid range, TTL out of range, expiry boundary, invalid jurisdiction, config versioning
- [x] Verifier upgrade scenarios (new verifier used, other types unaffected)
- [x] Fuzz: invalid proof type for verify and setVerifier
- [x] Circuit main() tests for all 6 circuits with valid witnesses

## Blocked

- [ ] **Generate UltraPlonk verifiers** -- bb >= 0.73 fails to extract on macOS ARM (tar format). bb 0.72.1 is incompatible with nargo 1.0.0-beta.19 artifacts. Unblocks: integration tests, real proof fixtures, testnet deployment.

## Next: Once bb is unblocked

- [ ] Generate verification keys: `bb write_vk` for each circuit
- [ ] Generate Solidity verifiers: `bb contract` -> `src/generated/`
- [ ] Create `scripts/generate-fixtures.sh` (Prover.toml -> witness -> proof -> fixtures)
- [ ] Write `test/Integration.t.sol` with real proof verification
- [ ] Update `script/Deploy.s.sol` to deploy generated verifiers + register them

## Short-term

- [ ] Add CI workflow (GitHub Actions: `forge test` + `nargo test`)
- [ ] Add `Makefile` with build/test/lint targets
- [ ] Add pre-commit hooks (solhint, forge fmt)

## Medium-term

- [ ] Client SDK (TypeScript): `@noir-lang/noir_js` + `@aztec/bb.js` wrapper
- [ ] Provider signal mock server for local development
- [ ] Gas benchmarks for each proof type verification
- [ ] Formal verification of jurisdiction threshold logic

## Pre-deployment

- [ ] Security audit (Solidity + Noir circuits)
- [ ] Testnet deployment (Sepolia, Base Sepolia)
- [ ] Documentation site
- [ ] EIP submission to ethereum/EIPs
- [ ] Timelock on admin operations (verifier updates, TTL changes)
- [ ] Multi-sig for oracle ownership

## Design decisions (documented, not bugs)

- **meetsThreshold always true**: Intentional -- failed proofs revert at verifier, so only compliant proofs are recorded. Field kept for checkCompliance() query interface.
- **No access control on submitCompliance()**: Anyone can prove compliance for themselves. Restricting to relayers would add centralization without security benefit.
- **keccak256(proof) as proof hash**: Different valid proofs for the same statement get different hashes. This is correct for replay protection and historical lookup.
- **Jurisdiction thresholds hardcoded**: By design per ERC spec. Updating requires contract upgrade, which is appropriate for regulatory thresholds.
- **No batch submission**: Multi-jurisdiction compliance requires separate transactions. Batch could be added later without breaking changes.
- **Pedersen vs Poseidon2**: Using Pedersen due to Noir API stability. Homomorphic properties documented as not exploitable in current circuit compositions. Migrate when Poseidon2 stabilizes.
