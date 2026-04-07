/// Membership proof circuit
///
/// Proves that an element (address, identifier) is a member of an authorized
/// set without revealing which element. The set is represented as a Merkle
/// tree; the prover supplies the leaf and a Merkle path to the public root.
///
/// Use cases:
/// - Whitelist verification (KYC-approved addresses)
/// - Authorized counterparty checks
/// - Approved token/pool inclusion
///
/// Public inputs:
///   - merkle_root: root of the membership set tree
///   - set_id: identifier for which set is being checked (e.g., whitelist version)
///   - timestamp: block timestamp for temporal binding
///   - is_member: boolean result
///
/// Private inputs:
///   - element: the value being checked for membership
///   - leaf_hash: hash of the element (the actual Merkle leaf)
///   - merkle_index: position in the tree
///   - merkle_path: sibling hashes along the path to root

use xochi_shared::{compute_merkle_root, hash2};

fn main(
    // --- Private ---
    element: Field,                    // the value being proven as a member
    merkle_index: Field,               // leaf position in the tree
    merkle_path: [Field; 20],          // MERKLE_DEPTH = 20

    // --- Public ---
    merkle_root: pub Field,            // root of the authorized set
    set_id: pub Field,                 // identifies which set (versioning)
    timestamp: pub Field,              // temporal binding
    is_member: pub bool,               // the result
) {
    // 1. Compute the leaf hash from the element
    //    leaf = H(element, set_id), binding the leaf to the specific set
    let leaf = hash2(element, set_id);

    // 2. Compute the Merkle root from the leaf and path
    let computed_root = compute_merkle_root(leaf, merkle_index, merkle_path);

    // 3. Verify membership: computed root must match the public root
    let membership_valid = computed_root == merkle_root;
    assert(membership_valid == is_member, "Membership result mismatch");

    // 4. Timestamp must be within reasonable bounds
    assert(timestamp as u64 > 1609459200, "Timestamp before 2021");
    assert(timestamp as u64 < 1099511627776, "Timestamp unreasonably far future"); // 2^40
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a simple 2-level Merkle tree for testing
/// Tree:        root
///            /      \
///         h01        h23
///        /   \      /   \
///      leaf0 leaf1 leaf2 leaf3
///
/// For MERKLE_DEPTH=20, we pad remaining levels with zero siblings.

#[test]
fn test_membership_valid() {
    // Element is in the set
    let element: Field = 42;
    let set_id: Field = 1;
    let leaf = hash2(element, set_id);

    // Build a trivial path: all siblings are zero (element is at index 0)
    let mut path: [Field; 20] = [0; 20];

    // Compute expected root by walking the tree
    let mut current = leaf;
    for _i in 0..20 {
        current = hash2(current, 0); // sibling is 0, we're always left child
    }
    let expected_root = current;

    // Verify: compute_merkle_root should produce the same root
    let computed = compute_merkle_root(leaf, 0, path);
    assert(computed == expected_root);
}

#[test]
fn test_membership_wrong_element() {
    // Element 42 is in the set, element 99 is not
    let real_element: Field = 42;
    let fake_element: Field = 99;
    let set_id: Field = 1;

    let real_leaf = hash2(real_element, set_id);
    let fake_leaf = hash2(fake_element, set_id);

    // They produce different leaves
    assert(real_leaf != fake_leaf);
}

#[test]
fn test_leaf_bound_to_set_id() {
    // Same element in different sets produces different leaves
    let element: Field = 42;
    let leaf_set1 = hash2(element, 1);
    let leaf_set2 = hash2(element, 2);
    assert(leaf_set1 != leaf_set2);
}

#[test]
fn test_main_valid_membership() {
    // Build a complete witness for main()
    let element: Field = 42;
    let set_id: Field = 1;
    let leaf = hash2(element, set_id);

    // Build Merkle path with all-zero siblings (element at index 0)
    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(leaf, 0, path);

    main(element, 0, path, root, set_id, 1700000000, true);
}

#[test]
fn test_main_invalid_membership() {
    // Wrong element doesn't match the root -> is_member = false
    let real_element: Field = 42;
    let fake_element: Field = 99;
    let set_id: Field = 1;
    let real_leaf = hash2(real_element, set_id);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(real_leaf, 0, path);

    // Fake element produces different root -> not a member
    main(fake_element, 0, path, root, set_id, 1700000000, false);
}
