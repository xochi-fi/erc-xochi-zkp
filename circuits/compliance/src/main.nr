/// Compliance proof circuit
///
/// Proves that a user's risk score (computed from screening provider signals)
/// is below the jurisdiction's high-risk threshold, without revealing:
/// - Individual provider signals
/// - The exact risk score
/// - Transaction amounts or counterparty details
///
/// Public inputs (visible to verifier):
///   - jurisdiction_id: which jurisdiction's thresholds to use
///   - provider_set_hash: commitment to which providers were used
///   - config_hash: hash of the published weight configuration
///   - timestamp: block timestamp binding the proof
///   - meets_threshold: boolean result (1 = compliant, 0 = not)
///
/// Private inputs (known only to prover):
///   - signals: risk scores from each screening provider (0-100)
///   - weights: published weights for each provider
///   - weight_sum: sum of all weights (for normalization)
///   - provider_ids: identifiers for each provider

use xochi_shared::{
    MAX_PROVIDERS,
    compute_risk_score,
    get_high_threshold,
    compute_provider_set_hash,
    hash8,
};

fn main(
    // --- Private inputs ---
    signals: [u32; 8],           // per-provider risk signals (0-100 each)
    weights: [u32; 8],           // per-provider weights (published, but hidden in proof)
    weight_sum: u32,             // sum of active weights
    provider_ids: [Field; 8],    // provider identifiers
    num_providers: u32,          // how many providers are active (1-8)

    // --- Public inputs ---
    jurisdiction_id: pub u8,     // 0=EU, 1=US, 2=UK, 3=SG
    provider_set_hash: pub Field, // commitment to providers used
    config_hash: pub Field,      // hash of the weight config version
    timestamp: pub Field,        // block.timestamp for temporal binding
    meets_threshold: pub bool,   // the compliance result
) {
    // 1. Validate provider count
    assert(num_providers >= 1, "At least one provider required");
    assert(num_providers <= MAX_PROVIDERS, "Too many providers");

    // 2. Validate weight_sum is positive
    assert(weight_sum > 0, "Weight sum must be positive");

    // 3. Validate signals and provider slots
    for i in 0..8 {
        if (i as u32) < num_providers {
            assert(signals[i] <= 100, "Signal must be 0-100");
            assert(weights[i] > 0, "Active provider weight must be positive");
            // Active providers must have non-zero IDs to prevent confusion
            // with inactive (zeroed) slots: a provider with ID=0 and weight=0
            // would be indistinguishable from an inactive slot in the hash.
            assert(provider_ids[i] != 0, "Active provider ID must be non-zero");
        } else {
            // Inactive provider slots must be zeroed
            assert(signals[i] == 0, "Inactive signal must be zero");
            assert(weights[i] == 0, "Inactive weight must be zero");
            assert(provider_ids[i] == 0, "Inactive provider ID must be zero");
        }
    }

    // 4. Verify weight_sum matches active weights
    let mut computed_weight_sum: u32 = 0;
    for i in 0..8 {
        computed_weight_sum += weights[i];
    }
    assert(computed_weight_sum == weight_sum, "Weight sum mismatch");

    // 5. Compute the risk score
    let score = compute_risk_score(signals, weights, weight_sum);

    // 6. Get the jurisdiction threshold
    let threshold = get_high_threshold(jurisdiction_id);

    // 7. Verify the meets_threshold claim
    let computed_meets = score < threshold;
    assert(computed_meets == meets_threshold, "Threshold result mismatch");

    // 8. Verify provider set hash matches the committed set
    let computed_provider_hash = compute_provider_set_hash(provider_ids, weights);
    assert(computed_provider_hash == provider_set_hash, "Provider set hash mismatch");

    // 9. Verify config hash commits to the weight configuration
    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let computed_config_hash = hash8(weight_fields);
    assert(computed_config_hash == config_hash, "Config hash mismatch");

    // 10. Timestamp must be within reasonable bounds
    assert(timestamp as u64 > 1609459200, "Timestamp before 2021");
    assert(timestamp as u64 < 1099511627776, "Timestamp unreasonably far future"); // 2^40
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_compliant_single_provider() {
    // Single provider, 20% risk signal, weight=100, weight_sum=100
    // score = 20*100*100/100 = 2000 bps (20%), EU threshold = 7100
    let signals = [20, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let score = compute_risk_score(signals, weights, 100);
    let threshold = get_high_threshold(0); // EU: 7100 bps
    assert(score == 2000);
    assert(score < threshold);
}

#[test]
fn test_non_compliant_high_risk() {
    // Single provider, 80% risk signal
    // score = 80*100*100/100 = 8000 bps (80%), EU threshold = 7100
    let signals = [80, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];

    let score = compute_risk_score(signals, weights, 100);
    assert(score == 8000);
    assert(score >= get_high_threshold(0)); // above EU threshold
}

#[test]
fn test_multi_provider_compliance() {
    // Three providers: signals=[10,30,20], weights=[50,30,20], weight_sum=100
    // weighted_sum = 10*50 + 30*30 + 20*20 = 500+900+400 = 1800
    // score = 1800*100/100 = 1800 bps (18%), well below any threshold
    let signals = [10, 30, 20, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [50, 30, 20, 0, 0, 0, 0, 0];

    let score = compute_risk_score(signals, weights, 100);
    assert(score == 1800);
    assert(score < get_high_threshold(0)); // below EU threshold
}

#[test]
fn test_main_compliant_single_provider() {
    // Full main() test with valid witness for single-provider compliance
    let signals = [20, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let weight_sum: u32 = 100;
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    let num_providers: u32 = 1;

    // Compute expected public inputs
    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config_hash = hash8(weight_fields);

    // score = 20*100*100/100 = 2000 bps, EU threshold = 7100 -> meets
    main(
        signals, weights, weight_sum, provider_ids, num_providers,
        0, // EU
        provider_set_hash,
        config_hash,
        1700000000, // timestamp
        true, // meets_threshold
    );
}

#[test]
fn test_main_non_compliant_high_risk() {
    // Full main() test for non-compliant result (score above threshold)
    let signals = [80, 0, 0, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [100, 0, 0, 0, 0, 0, 0, 0];
    let weight_sum: u32 = 100;
    let provider_ids: [Field; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config_hash = hash8(weight_fields);

    // score = 8000 bps, EU threshold = 7100 -> does NOT meet
    main(
        signals, weights, weight_sum, provider_ids, 1,
        0, // EU
        provider_set_hash,
        config_hash,
        1700000000,
        false, // does not meet threshold
    );
}

#[test]
fn test_main_multi_provider_all_jurisdictions() {
    // 3 providers, test all 4 jurisdictions
    let signals = [30, 40, 20, 0, 0, 0, 0, 0];
    let weights: [u32; 8] = [50, 30, 20, 0, 0, 0, 0, 0];
    let weight_sum: u32 = 100;
    let provider_ids: [Field; 8] = [10, 20, 30, 0, 0, 0, 0, 0];

    let provider_set_hash = compute_provider_set_hash(provider_ids, weights);
    let mut weight_fields: [Field; 8] = [0; 8];
    for i in 0..8 {
        weight_fields[i] = weights[i] as Field;
    }
    let config_hash = hash8(weight_fields);

    // weighted_sum = 30*50 + 40*30 + 20*20 = 1500+1200+400 = 3100
    // score = 3100*100/100 = 3100 bps (31%), below all thresholds
    for j in 0..4 {
        main(
            signals, weights, weight_sum, provider_ids, 3,
            j as u8,
            provider_set_hash,
            config_hash,
            1700000000,
            true,
        );
    }
}
