/// Risk score computation circuit
///
/// Standalone circuit that proves a risk score was correctly computed
/// from provider signals and published weights, without revealing
/// individual signals or the exact score.
///
/// Use cases:
/// - Threshold proof: score > X or score < X
/// - Range proof: score in [X, Y]
///
/// Public inputs:
///   - proof_type: 0x01 (threshold) or 0x02 (range)
///   - direction: for threshold -- 1=GT, 2=LT
///   - bound_lower: lower bound (threshold value for 0x01, range floor for 0x02)
///   - bound_upper: upper bound (unused for 0x01, range ceiling for 0x02)
///   - result: boolean -- does the score satisfy the condition?
///   - config_hash: hash of published weight configuration
///
/// Private inputs:
///   - signals: per-provider risk signals
///   - weights: per-provider weights
///   - weight_sum: normalization factor

use xochi_shared::{compute_risk_score, hash8};

/// Threshold proof type
global PROOF_THRESHOLD: u8 = 0x01;
/// Range proof type
global PROOF_RANGE: u8 = 0x02;
/// Direction: greater than
global DIRECTION_GT: u8 = 1;
/// Direction: less than
global DIRECTION_LT: u8 = 2;

fn main(
    // --- Private ---
    signals: [u32; 8],
    weights: [u32; 8],
    weight_sum: u32,

    // --- Public ---
    proof_type: pub u8,       // 0x01=threshold, 0x02=range
    direction: pub u8,        // 1=GT, 2=LT (only for threshold)
    bound_lower: pub u32,     // threshold or range lower bound (in basis points)
    bound_upper: pub u32,     // range upper bound (in basis points, 0 for threshold)
    result: pub bool,         // does the score satisfy the condition?
    config_hash: pub Field,   // published weight config hash
) {
    // 1. Validate inputs
    assert(weight_sum > 0, "Weight sum must be positive");
    assert(
        (proof_type == PROOF_THRESHOLD) | (proof_type == PROOF_RANGE),
        "Invalid proof type",
    );

    for i in 0..8 {
        assert(signals[i] <= 100, "Signal out of range");
    }

    // Verify weight_sum matches actual sum of weights (prevents prover from
    // passing an arbitrary denominator to inflate/deflate the score)
    let mut computed_weight_sum: u32 = 0;
    for i in 0..8 {
        computed_weight_sum += weights[i];
    }
    assert(computed_weight_sum == weight_sum, "Weight sum mismatch");

    // 2. Compute the risk score
    let score = compute_risk_score(signals, weights, weight_sum);

    // 3. Verify the claimed result
    if proof_type == PROOF_THRESHOLD {
        if direction == DIRECTION_GT {
            assert(result == (score > bound_lower), "Threshold GT mismatch");
        } else if direction == DIRECTION_LT {
            assert(result == (score < bound_lower), "Threshold LT mismatch");
        } else {
            assert(false, "Invalid direction");
        }
    } else {
        // Range proof: score in [bound_lower, bound_upper]
        assert(bound_upper >= bound_lower, "Invalid range");
        let in_range = (score >= bound_lower) & (score <= bound_upper);
        assert(result == in_range, "Range mismatch");
    }

    // 4. Verify config hash
    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let computed_config = hash8(weight_fields);
    assert(computed_config == config_hash, "Config hash mismatch");
}

#[test]
fn test_threshold_gt_true() {
    let signals = [60, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    // score = 60*100*100/100 = 6000 bps
    let score = compute_risk_score(signals, weights, 100);
    assert(score == 6000);
    assert(score > 5000); // GT 50%
}

#[test]
fn test_threshold_lt_true() {
    let signals = [20, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let score = compute_risk_score(signals, weights, 100);
    assert(score == 2000);
    assert(score < 5000); // LT 50%
}

#[test]
fn test_range_in_bounds() {
    let signals = [45, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let score = compute_risk_score(signals, weights, 100);
    assert(score == 4500);
    assert((score >= 4000) & (score <= 5000)); // in [40%, 50%]
}

#[test]
fn test_main_threshold_gt() {
    let signals = [60, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config = hash8(weight_fields);

    // score = 6000 > 5000
    main(signals, weights, 100, PROOF_THRESHOLD, DIRECTION_GT, 5000, 0, true, config);
}

#[test]
fn test_main_threshold_lt() {
    let signals = [20, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config = hash8(weight_fields);

    // score = 2000 < 5000
    main(signals, weights, 100, PROOF_THRESHOLD, DIRECTION_LT, 5000, 0, true, config);
}

#[test]
fn test_main_range_proof() {
    let signals = [45, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config = hash8(weight_fields);

    // score = 4500, in [4000, 5000]
    main(signals, weights, 100, PROOF_RANGE, 0, 4000, 5000, true, config);
}

#[test(should_fail_with = "Weight sum mismatch")]
fn test_main_revert_weight_sum_mismatch() {
    let signals = [60, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config = hash8(weight_fields);

    // Pass weight_sum=1 instead of correct 100 -- should fail
    main(signals, weights, 1, PROOF_THRESHOLD, DIRECTION_GT, 0, 0, true, config);
}

#[test]
fn test_main_range_proof_out_of_bounds() {
    let signals = [60, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config = hash8(weight_fields);

    // score = 6000, NOT in [4000, 5000]
    main(signals, weights, 100, PROOF_RANGE, 0, 4000, 5000, false, config);
}
