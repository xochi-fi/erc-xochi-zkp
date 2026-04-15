# erc-xochi-zkp

Reference implementation for the Xochi ZKP Compliance Oracle, a standard for zero-knowledge compliance proofs on Ethereum.

## What this is

A system where a user proves they're AML/sanctions-compliant without revealing any transaction data. The regulator verifies a ZK proof. They never see the trade.

This is distinct from view keys (Railgun, Panther) where you trade privately and then reveal transactions to auditors on request. Xochi ZKP never reveals the data. Compliance is proven cryptographically at transaction time, not reconstructed after the fact.

## Proof types

| Type           | ID   | Assertion                         | What stays hidden   | Circuit        |
| -------------- | ---- | --------------------------------- | ------------------- | -------------- |
| Compliance     | 0x01 | "Risk score below threshold"      | Signals, score      | compliance     |
| Risk Score     | 0x02 | "Score > X" or "Score in [X,Y]"   | Exact score         | risk_score     |
| Pattern        | 0x03 | "No structuring detected"         | Transaction history | pattern        |
| Attestation    | 0x04 | "Valid credential exists"         | Credential details  | attestation    |
| Membership     | 0x05 | "Address in authorized set S"     | Which element       | membership     |
| Non-membership | 0x06 | "Address NOT in sanctions list S" | List contents       | non_membership |

## How it works

```
User's client fetches signed risk signals from screening providers
  -> Computes risk score locally (deterministic formula, published weights)
  -> Generates ZK proof (Noir circuit, UltraHonk backend) that:
       - Signal values were used (hidden)
       - Published weights were applied correctly (public config hash)
       - Score meets jurisdiction threshold (boolean: yes/no)
  -> Proof submitted on-chain to XochiZKPOracle
  -> Oracle routes to the correct UltraHonk verifier via XochiZKPVerifier
  -> Attestation recorded on-chain (subject, jurisdiction, timestamp, proof hash)
```

The proof also commits to a timestamp and the screening providers used, enabling retroactive proof-of-innocence if a counterparty is later flagged.

## Architecture

```solidity
                  +------------------+
                  | XochiZKPOracle   |  <-
                  | (attestation     |  // submitCompliance(), checkCompliance(),
                  |  storage +       |  // getHistoricalProof()
                  |  input validation|  // validates config hashes, merkle roots,
                  |  + registries)   |  // reporting thresholds per proof type
                  +--------+---------+
                           |
                           | IUltraVerifier.verify() (view, direct call)
                           v
     +---------+---------+---------+---------+---------+---------+
     |         |         |         |         |         |         |
     v         v         v         v         v         v         v
     +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +--------+
     |Compli-| |Risk   | |Pattern| |Attest.| |Member | |Non-   | |Verifier|
     |ance   | |Score  | |       | |       | |ship   | |member | |Router  |
     +-------+ +-------+ +-------+ +-------+ +-------+ +-------+ +--------+
     Generated UltraHonk verifiers (bb write_solidity_verifier)
```

Each of the 6 proof types has its own Noir circuit and generates a separate UltraHonk verifier contract via Barretenberg (`bb write_solidity_verifier`).

## SettlementRegistry

Standalone immutable contract that links split settlement proofs to a tradeId (XIP-1). When a large trade is split into sub-trades for privacy, the registry records each sub-trade's compliance proof and enforces an anti-structuring pattern proof at finalization.

- No admin, no pause, no upgradability -- fully immutable
- References the Oracle via `getHistoricalProof()` to validate proof existence
- Interface: `ISettlementRegistry`
- Test: `forge test --match-contract SettlementRegistry` (40 tests)

## Repository structure

```bash
/
  Makefile                        # Build/test/lint targets (make help)
  foundry.toml                    # Foundry project config
  eip-draft_xochi-zkp.md          # The EIP document itself
  src/
    interfaces/
      IXochiZKPVerifier.sol       # Verifier interface (ERC standard)
      IXochiZKPOracle.sol         # Oracle interface (ERC standard)
      IUltraVerifier.sol          # Interface for generated verifiers
      ISettlementRegistry.sol     # Settlement registry interface
    libraries/
      ProofTypes.sol              # Proof type definitions and encoding
      JurisdictionConfig.sol      # Threshold configurations per jurisdiction
    XochiZKPVerifier.sol          # Reference verifier (routes to UltraHonk)
    XochiZKPOracle.sol            # Reference oracle (attestation storage)
    SettlementRegistry.sol        # Immutable registry linking split settlement proofs to a tradeId
    generated/                    # Auto-generated UltraHonk verifiers (do not edit)
  test/
    XochiZKPVerifier.t.sol        # Verifier unit tests
    XochiZKPOracle.t.sol          # Oracle unit + fuzz + invariant tests
    SettlementRegistry.t.sol      # Settlement registry tests (40 tests)
    Integration.t.sol             # End-to-end tests with real proofs
    fixtures/                     # Test proof fixtures (generated by scripts/generate-fixtures.sh)
    sdk/                          # TypeScript consumer SDK tests (noir_js + bb.js + anvil)
  script/
    Deploy.s.sol                  # Deployment script
  circuits/
    Nargo.toml                    # Workspace config (nargo compile/test --workspace)
    shared/                       # Shared Noir library
      src/lib.nr                  # Re-exports all modules
      src/hash.nr                 # Pedersen hash wrappers (hash2..hash32)
      src/merkle.nr               # Merkle root computation
      src/risk.nr                 # Risk score + jurisdiction thresholds
      src/providers.nr             # Provider set commitment
      src/constants.nr             # Shared constants (jurisdictions, depths, limits)
    compliance/                   # Compliance proof circuit (0x01)
      src/main.nr                 # Risk score below jurisdiction threshold
    risk_score/                   # Risk score circuit (0x02)
      src/main.nr                 # Threshold and range proofs
    pattern/                      # Pattern detection circuit (0x03)
      src/main.nr                 # Structuring, velocity, round-amount analysis
    attestation/                  # Attestation circuit (0x04)
      src/main.nr                 # KYC tier, accreditation proofs
    membership/                   # Membership proof circuit (0x05)
      src/main.nr                 # Merkle inclusion proof for authorized sets
    non_membership/               # Non-membership proof circuit (0x06)
      src/main.nr                 # Sorted Merkle adjacency proof for exclusion
```

## Jurisdiction thresholds

Risk scores are in basis points (0-10000 = 0.00%-100.00%). Thresholds are published on-chain.

| Jurisdiction | Low        | Medium    | High (filing trigger) |
| ------------ | ---------- | --------- | --------------------- |
| EU (AMLD6)   | 0-3099 bps | 3100-7099 | >=7100                |
| US (BSA)     | 0-2599 bps | 2600-6599 | >=6600                |
| UK (MLR)     | 0-3099 bps | 3100-7099 | >=7100                |
| Singapore    | 0-3599 bps | 3600-7599 | >=7600                |

## Development

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast, anvil)
- [Noir](https://noir-lang.org/docs/getting_started/installation) (nargo >= 1.0.0)
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (bb)

### Setup

```bash
# Install Solidity dependencies
forge install

# Install TS SDK test dependencies (optional, for make test-sdk)
npm install

# Build everything
make build

# Run Solidity tests
make test

# Run all tests (Solidity + Noir + TS SDK)
make test-all

# See all targets
make help
```

### Circuit development

```bash
# Compile all circuits (workspace)
cd circuits && nargo compile --workspace

# Run all circuit tests (workspace)
cd circuits && nargo test --workspace

# Compile/test a single circuit
cd circuits/compliance && nargo compile
cd circuits/compliance && nargo test

# Generate witness (requires Prover.toml with inputs)
cd circuits/compliance && nargo execute

# Generate fixtures + verifier for a single circuit (recommended)
./scripts/generate-fixtures.sh compliance

# Generate fixtures + verifiers for all circuits
./scripts/generate-fixtures.sh
```

### Deployment

```bash
# Copy and fill in environment variables
cp .env.example .env

# Deploy to testnet
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast

# After deploying generated verifiers, register them:
cast send $VERIFIER_ADDR "setVerifier(uint8,address)" 0x01 $THRESHOLD_VERIFIER
```

## Client-side proof generation

Proofs are generated client-side using `@noir-lang/noir_js` and `@aztec/bb.js`:

```typescript
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import circuit from "./circuits/compliance/target/compliance.json";

const api = await Barretenberg.new();
const noir = new Noir(circuit);
const backend = new UltraHonkBackend(circuit.bytecode, api);

// Private inputs never leave the client
const inputs = {
  signals: ["20", "30", "10", "0", "0", "0", "0", "0"],
  weights: ["50", "30", "20", "0", "0", "0", "0", "0"],
  weight_sum: "100",
  provider_ids: ["1", "2", "3", "0", "0", "0", "0", "0"],
  num_providers: "3",
  // Public inputs
  jurisdiction_id: "0", // EU
  provider_set_hash: "0x...",
  config_hash: "0x...",
  timestamp: "1700000000",
  meets_threshold: "1",
};

const { witness } = await noir.execute(inputs);
const proof = await backend.generateProof(witness, { verifierTarget: "evm" });

// Submit proof.proof and proof.publicInputs to XochiZKPOracle.submitCompliance()
await api.destroy();
```

A higher-level SDK is available at [`@xochi/sdk`](../xochi-sdk) with typed input builders and automatic validation.

## Retroactive flagging

Sanctions lists update continuously. An address clean at T=transaction may be flagged at T+90 days. Each compliance attestation records:

1. Which screening providers were queried (provider set hash)
2. The oracle's clearing decision (meetsThreshold boolean)
3. A timestamp binding the proof to that block
4. The full proof hash for retrieval via `getHistoricalProof()`

Counterparties retrieve the original attestation to demonstrate they couldn't have known. The proof is immutable on-chain.

## Deployments

_Testnet deployments pending. Mainnet after audit._

| Network      | Verifier | Oracle | Explorer |
| ------------ | -------- | ------ | -------- |
| Sepolia      | TBD      | TBD    | --       |
| Base Sepolia | TBD      | TBD    | --       |

## Related

- [ERC Draft](eip-draft_xochi-zkp.md): the EIP specification
- [nahualli](https://github.com/xochi-fi/nahualli): vanity stealth key grinder for ERC-5564
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564): stealth addresses (complementary)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538): stealth meta-address registry
- [Noir Language](https://noir-lang.org/): ZK circuit language by Aztec
- [Barretenberg](https://github.com/AztecProtocol/aztec-packages): UltraHonk proving backend

## Security

No external audit has been performed yet. Do not use in production.
If you find a vulnerability, email security@xochi.fi.

## License

Reference implementation: [CC0-1.0](LICENSE) (public domain).
