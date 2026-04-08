/// Merkle tree utilities for Xochi ZKP circuits

use crate::hash::hash2;

/// Compute the Merkle root from a leaf, index, and sibling path using Pedersen.
///
/// The leaf's position in the tree is encoded as `index` in little-endian bits.
/// At each level `i`, bit `i` of `index` determines the node's position:
///   - bit = 0: current node is the LEFT child, sibling is right
///   - bit = 1: current node is the RIGHT child, sibling is left
///
/// This walks from leaf to root, hashing with each sibling along the path.
/// The computed root is compared against a public Merkle root to prove membership.
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
