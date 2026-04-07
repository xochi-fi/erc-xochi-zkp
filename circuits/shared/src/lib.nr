/// Shared types and utilities for Xochi ZKP circuits
///
/// All circuits use Pedersen hash (efficient in ZK circuits, publicly available in Noir stdlib).
/// Field elements correspond to BN254 scalar field (~254 bits).
///
/// Note: Poseidon2 is preferred for ZK efficiency but its high-level API is private
/// in Noir 1.0.0-beta. When Noir stabilizes, swap pedersen_hash for Poseidon2::hash.
///
/// SECURITY NOTE on Pedersen hash:
/// Pedersen commitments are additively homomorphic: H(a) + H(b) = H(a+b) for the
/// underlying elliptic curve points. This is NOT exploitable in our circuits because:
///   1. We never expose raw hash outputs to user-controlled arithmetic.
///   2. All hashes are used as opaque commitments compared via equality (== merkle_root).
///   3. No circuit composes hashes in a way that allows the prover to exploit linearity
///      (e.g., no circuit checks H(x) + H(y) == H(z)).
///   4. Second-preimage resistance holds because all hash calls use fixed-arity inputs
///      (hash2, hash3, etc.), so different (a, b) pairs cannot be reinterpreted as (c).
/// When Poseidon2 becomes available, migrate to it for stronger random-oracle properties.

use std::hash::pedersen_hash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of screening providers supported
pub global MAX_PROVIDERS: u32 = 8;

/// Merkle tree depth for membership/non-membership proofs
pub global MERKLE_DEPTH: u32 = 20;

/// Maximum number of transactions for anti-structuring analysis
pub global MAX_TRANSACTIONS: u32 = 16;

/// Jurisdiction IDs (must match Solidity JurisdictionConfig)
pub global JURISDICTION_EU: u8 = 0;
pub global JURISDICTION_US: u8 = 1;
pub global JURISDICTION_UK: u8 = 2;
pub global JURISDICTION_SG: u8 = 3;

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Hash two field elements
pub fn hash2(a: Field, b: Field) -> Field {
    pedersen_hash([a, b])
}

/// Hash three field elements
pub fn hash3(a: Field, b: Field, c: Field) -> Field {
    pedersen_hash([a, b, c])
}

/// Hash four field elements
pub fn hash4(a: Field, b: Field, c: Field, d: Field) -> Field {
    pedersen_hash([a, b, c, d])
}

/// Hash an 8-element field array
pub fn hash8(input: [Field; 8]) -> Field {
    pedersen_hash(input)
}

/// Hash a 16-element field array
pub fn hash16(input: [Field; 16]) -> Field {
    pedersen_hash(input)
}

/// Hash a 32-element field array
pub fn hash32(input: [Field; 32]) -> Field {
    pedersen_hash(input)
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// Compute the Merkle root from a leaf, index, and sibling path using Pedersen
/// The index bits determine whether the current node is left (0) or right (1)
pub fn compute_merkle_root<let DEPTH: u32>(
    leaf: Field,
    index: Field,
    hash_path: [Field; DEPTH],
) -> Field {
    let index_bits: [u1; DEPTH] = index.to_le_bits();
    let mut current = leaf;
    for i in 0..DEPTH {
        let sibling = hash_path[i];
        let (left, right) = if index_bits[i] == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        current = hash2(left, right);
    }
    current
}

// ---------------------------------------------------------------------------
// Risk score computation
// ---------------------------------------------------------------------------

/// Maximum weight per provider (prevents u32 overflow in risk score computation).
/// With N=8 providers, max signal=100: worst case = 8 * 100 * MAX_WEIGHT = 8 * 100 * 10000
/// = 8,000,000. Then * 100 = 800,000,000, well within u32 max (4,294,967,295).
pub global MAX_WEIGHT: u32 = 10000;

/// Compute a weighted risk score from provider signals and weights
/// Signals are 0-100 (percentage risk from each provider)
/// Weights are importance factors that sum to weight_sum (each <= MAX_WEIGHT)
/// Returns the score as a u32 in basis points (0-10000, i.e. 0.00%-100.00%)
pub fn compute_risk_score<let N: u32>(
    signals: [u32; N],
    weights: [u32; N],
    weight_sum: u32,
) -> u32 {
    let mut weighted_sum: u32 = 0;
    for i in 0..N {
        assert(weights[i] <= MAX_WEIGHT, "Weight exceeds maximum");
        weighted_sum += signals[i] * weights[i];
    }
    // signals are 0-100, so multiply by 100 to get basis points
    // score_bps = sum(signal_i * weight_i) * 100 / weight_sum
    // Overflow safe: max weighted_sum = 8 * 100 * 10000 = 8M, * 100 = 800M < u32::MAX
    (weighted_sum * 100) / weight_sum
}

/// Get the high-risk threshold for a jurisdiction (in basis points)
/// Must match Solidity JurisdictionConfig thresholds
pub fn get_high_threshold(jurisdiction_id: u8) -> u32 {
    if jurisdiction_id == JURISDICTION_EU {
        7100 // 71%
    } else if jurisdiction_id == JURISDICTION_US {
        6600 // 66%
    } else if jurisdiction_id == JURISDICTION_UK {
        7100 // 71%
    } else if jurisdiction_id == JURISDICTION_SG {
        7600 // 76%
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Provider set commitment
// ---------------------------------------------------------------------------

/// Compute a commitment to the set of providers and weights used.
/// N must be <= MAX_PROVIDERS (8), since the hash uses a fixed 16-slot array
/// (2 slots per provider: id + weight).
pub fn compute_provider_set_hash<let N: u32>(
    provider_ids: [Field; N],
    weights: [u32; N],
) -> Field {
    assert(N <= MAX_PROVIDERS, "Provider count exceeds MAX_PROVIDERS");
    let mut hash_inputs: [Field; 16] = [0; 16];
    for i in 0..N {
        hash_inputs[i * 2] = provider_ids[i];
        hash_inputs[i * 2 + 1] = weights[i] as Field;
    }
    hash16(hash_inputs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_hash2_deterministic() {
    let h1 = hash2(1, 2);
    let h2 = hash2(1, 2);
    assert(h1 == h2);
}

#[test]
fn test_hash2_different_inputs() {
    let h1 = hash2(1, 2);
    let h2 = hash2(2, 1);
    assert(h1 != h2);
}

#[test]
fn test_risk_score_basic() {
    let score = compute_risk_score([50], [100], 100);
    assert(score == 5000);
}

#[test]
fn test_risk_score_multi_provider() {
    let score = compute_risk_score([30, 70], [60, 40], 100);
    assert(score == 4600);
}

#[test]
fn test_high_threshold_eu() {
    assert(get_high_threshold(JURISDICTION_EU) == 7100);
}

#[test]
fn test_high_threshold_us() {
    assert(get_high_threshold(JURISDICTION_US) == 6600);
}
