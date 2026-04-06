# erc-xochi-zkp

Reference implementation for the Xochi ZKP Compliance Oracle -- a standard for zero-knowledge compliance proofs on Ethereum.

## What this is

A system where a user proves they're AML/sanctions-compliant without revealing any transaction data. The regulator verifies a ZK proof. They never see the trade.

This is distinct from view keys (Railgun, Panther) where you trade privately and then reveal transactions to auditors on request. Xochi ZKP never reveals the data. Compliance is proven cryptographically at transaction time, not reconstructed after the fact.

## Proof types

| Type           | Assertion                         | What stays hidden   |
| -------------- | --------------------------------- | ------------------- |
| Threshold      | "Amount > X" or "Amount < X"      | Exact amount        |
| Range          | "Amount in [X, Y]"                | Exact amount        |
| Membership     | "Address in set S"                | Which element       |
| Non-membership | "Address NOT in sanctions list S" | List contents       |
| Pattern        | "No structuring detected"         | Transaction history |
| Attestation    | "Valid credential exists"         | Credential details  |

## How it works

```
User's client fetches signed risk signals from screening providers
  -> Computes risk score locally (deterministic formula, published weights)
  -> Generates ZK proof that:
       - Signal values were used (hidden)
       - Published weights were applied correctly (public)
       - Score meets jurisdiction threshold (boolean: yes/no)
  -> Proof submitted on-chain or to verifier
  -> Verifier confirms proof without learning inputs or exact score
```

The proof also commits to a timestamp and the screening providers used, enabling retroactive proof-of-innocence if a counterparty is later flagged.

## Retroactive flagging

Sanctions lists update continuously. An address clean at T=transaction may be flagged at T+90 days. Each transaction's ZK proof commits to:

1. Which screening providers were queried
2. What each returned at T=transaction (clean/flagged)
3. The oracle's clearing decision
4. A timestamp binding the proof to that moment

When an address is retroactively flagged, counterparties retrieve the original proof and present it to enforcement. It mathematically demonstrates they couldn't have known. Enforcement can also deconstruct the proof to see which providers the flagged party was using -- useful for identifying screening gaps without compromising uninvolved parties.

## Provider weight tuning

Provider weights aren't static. When retroactively flagged transactions are deconstructed, the providers involved get logged. Providers that consistently appear in flagged transactions get down-weighted. All weight changes are versioned, timestamped, and published openly. The system self-improves from enforcement data.

## Jurisdiction thresholds

| Jurisdiction | Low  | Medium | High | Filing trigger |
| ------------ | ---- | ------ | ---- | -------------- |
| EU (AMLD6)   | 0-30 | 31-70  | >70  | High           |
| US (BSA)     | 0-25 | 26-65  | >65  | High           |
| UK (MLR)     | 0-30 | 31-70  | >70  | High           |
| Singapore    | 0-35 | 36-75  | >75  | High           |

## Repository structure

```
/
  README.md
  LICENSE                          # CC0-1.0 (public domain)
  eip-draft_xochi-zkp.md          # The EIP document itself
  src/
    IXochiZKPVerifier.sol          # Verifier interface
    IXochiZKPOracle.sol            # Oracle interface
    XochiZKPVerifier.sol           # Reference verifier
    XochiZKPOracle.sol             # Reference oracle
    libraries/
      ProofTypes.sol               # Proof type definitions
      JurisdictionConfig.sol       # Threshold configurations
  test/
    XochiZKPVerifier.t.sol         # Verifier tests
    XochiZKPOracle.t.sol           # Oracle tests
    fixtures/                      # Test proof fixtures
  script/
    Deploy.s.sol                   # Deployment script
  circuits/
    compliance.nr                  # Noir circuit: compliance proof
    anti_structuring.nr            # Noir circuit: structuring detection
    risk_score.nr                  # Noir circuit: risk score computation
    tier_verification.nr           # Noir circuit: trust tier proof
  foundry.toml
```

## Development

```bash
# Build
forge build

# Test
forge test

# Coverage
forge coverage

# Compile Noir circuits
cd circuits && nargo compile

# Deploy (testnet)
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Deployments

_Testnet deployments pending. Mainnet after audit._

| Network      | Verifier | Oracle | Explorer |
| ------------ | -------- | ------ | -------- |
| Sepolia      | TBD      | TBD    | --       |
| Base Sepolia | TBD      | TBD    | --       |

## Related

- [Xochi Whitepaper](https://xochi.fi/whitepaper) -- full protocol specification
- [ZKSAR Framework](https://github.com/xochi-fi/xochi) -- zero-knowledge compliance framework docs
- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) -- stealth addresses (used by Xochi for L1 privacy)
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) -- stealth meta-address registry
- [ScopeLift stealth-address-sdk](https://github.com/ScopeLift/stealth-address-sdk) -- canonical ERC-5564/6538 TypeScript implementation

## Security

No audit has been performed yet. Do not use in production.

If you find a vulnerability, email security@xochi.fi.

## License

Reference implementation: [CC0-1.0](LICENSE) (public domain).

The Xochi ZKP standard is free to implement. Build on it.
