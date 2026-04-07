/// Non-membership proof circuit
///
/// Proves that an element is NOT in a set (e.g., sanctions list) without
/// revealing the element or the list contents. Uses a sorted Merkle tree
/// where leaves are ordered by value. Non-membership is proven by showing
/// two adjacent leaves (low_leaf, high_leaf) such that:
///   low_leaf < element < high_leaf
/// and both leaves are valid members of the tree.
///
/// This is the standard sorted-list non-membership technique used in
/// Indexed Merkle Trees (similar to Aztec's approach).
///
/// SECURITY: All values (element, low_leaf, high_leaf) MUST fit in u64.
/// This is enforced by range constraints in the circuit. Values are typically
/// Ethereum addresses (160-bit) or identifiers that naturally fit in u64.
/// The sorted Merkle tree construction must ensure all inserted values are < 2^64.
///
/// Public inputs:
///   - merkle_root: root of the sorted set tree (e.g., sanctions list)
///   - set_id: identifier for which set (e.g., OFAC list version)
///   - timestamp: block timestamp for temporal binding
///   - is_non_member: boolean result (true = element is NOT in the set)
///
/// Private inputs:
///   - element: the value being checked
///   - low_leaf: the largest leaf value less than element
///   - high_leaf: the smallest leaf value greater than element
///   - low_index: Merkle index of low_leaf
///   - low_path: Merkle path for low_leaf
///   - high_index: Merkle index of high_leaf
///   - high_path: Merkle path for high_leaf

use xochi_shared::{compute_merkle_root, hash2};

/// Maximum value that can be stored in the sorted Merkle tree.
/// All elements must fit in u64 for safe ordering comparisons.
global MAX_ELEMENT_VALUE: Field = 18446744073709551615; // 2^64 - 1

fn main(
    // --- Private ---
    element: Field,
    low_leaf: Field,                   // largest value < element
    high_leaf: Field,                  // smallest value > element
    low_index: Field,                  // Merkle position of low_leaf
    low_path: [Field; 20],            // MERKLE_DEPTH = 20
    high_index: Field,                // Merkle position of high_leaf
    high_path: [Field; 20],           // MERKLE_DEPTH = 20

    // --- Public ---
    merkle_root: pub Field,           // root of the sorted set
    set_id: pub Field,                // identifies which set
    timestamp: pub Field,             // temporal binding
    is_non_member: pub bool,          // the result
) {
    // 1. Timestamp must be within reasonable bounds
    assert(timestamp as u64 > 1609459200, "Timestamp before 2021");
    assert(timestamp as u64 < 1099511627776, "Timestamp unreasonably far future"); // 2^40

    // 2. Range-check: all values must fit in u64 to prevent truncation attacks.
    //    Without this, an attacker could craft a ~254-bit Field value that
    //    collides with a different value after u64 truncation.
    assert(element.lt(MAX_ELEMENT_VALUE + 1), "Element exceeds u64 range");
    assert(low_leaf.lt(MAX_ELEMENT_VALUE + 1), "Low leaf exceeds u64 range");
    assert(high_leaf.lt(MAX_ELEMENT_VALUE + 1), "High leaf exceeds u64 range");

    // 3. Compute leaf hashes (binding to set_id)
    let low_leaf_hash = hash2(low_leaf, set_id);
    let high_leaf_hash = hash2(high_leaf, set_id);

    // 4. Verify ordering: low_leaf < element < high_leaf
    //    Safe after range-check: u64 cast cannot truncate.
    let ordering_valid = (low_leaf as u64 < element as u64)
        & (element as u64 < high_leaf as u64);

    // 5. Verify low_leaf is in the tree
    let low_root = compute_merkle_root(low_leaf_hash, low_index, low_path);
    let low_valid = low_root == merkle_root;

    // 6. Verify high_leaf is in the tree
    let high_root = compute_merkle_root(high_leaf_hash, high_index, high_path);
    let high_valid = high_root == merkle_root;

    // 7. Non-membership holds if ordering is valid AND both neighbors are in the tree
    let computed_non_member = ordering_valid & low_valid & high_valid;
    assert(computed_non_member == is_non_member, "Non-membership result mismatch");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_ordering_check() {
    // low=10, element=50, high=100 -> valid ordering
    let low: u64 = 10;
    let elem: u64 = 50;
    let high: u64 = 100;
    assert((low < elem) & (elem < high));
}

#[test]
fn test_ordering_fails_when_element_equals_leaf() {
    // If element == low_leaf, ordering check fails (not strictly less than)
    let low: u64 = 50;
    let elem: u64 = 50;
    let high: u64 = 100;
    assert(!((low < elem) & (elem < high)));
}

#[test]
fn test_ordering_fails_when_element_outside_range() {
    // element=200, not between low=10 and high=100
    let low: u64 = 10;
    let elem: u64 = 200;
    let high: u64 = 100;
    assert(!((low < elem) & (elem < high)));
}

#[test]
fn test_leaf_hash_bound_to_set() {
    // Same value in different sets produces different leaf hashes
    let val: Field = 42;
    let h1 = hash2(val, 1);
    let h2 = hash2(val, 2);
    assert(h1 != h2);
}

#[test]
fn test_ordering_fails_when_leaves_equal() {
    // If low_leaf == high_leaf, there's no room for element
    let low: u64 = 50;
    let elem: u64 = 50;
    let high: u64 = 50;
    assert(!((low < elem) & (elem < high)));
}

#[test]
fn test_ordering_adjacent_values() {
    // low=49, element=50, high=51 -> valid (tight gap)
    let low: u64 = 49;
    let elem: u64 = 50;
    let high: u64 = 51;
    assert((low < elem) & (elem < high));
}

#[test]
fn test_ordering_boundary_u64_max() {
    // Element near u64 max boundary
    let low: u64 = 18446744073709551613; // 2^64 - 3
    let elem: u64 = 18446744073709551614; // 2^64 - 2
    let high: u64 = 18446744073709551615; // 2^64 - 1
    assert((low < elem) & (elem < high));
}

#[test]
fn test_main_valid_non_membership() {
    // Prove element=50 is not in a set containing {10, 100}
    let element: Field = 50;
    let low_leaf: Field = 10;
    let high_leaf: Field = 100;
    let set_id: Field = 1;

    let low_leaf_hash = hash2(low_leaf, set_id);
    let high_leaf_hash = hash2(high_leaf, set_id);

    // Build consistent Merkle tree:
    // Index 0: low_leaf_hash, Index 1: high_leaf_hash
    // At level 0, low's sibling is high, and high's sibling is low.
    let mut low_path: [Field; 20] = [0; 20];
    low_path[0] = high_leaf_hash; // sibling of index 0 at level 0

    let mut high_path: [Field; 20] = [0; 20];
    high_path[0] = low_leaf_hash; // sibling of index 1 at level 0

    let root = compute_merkle_root(low_leaf_hash, 0, low_path);

    main(
        element, low_leaf, high_leaf,
        0, low_path,     // low at index 0
        1, high_path,    // high at index 1
        root, set_id, 1700000000, true,
    );
}
