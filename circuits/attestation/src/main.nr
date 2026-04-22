/// Attestation circuit (credential/tier verification)
///
/// Proves that a user holds a valid credential from an authorized provider
/// without revealing the credential details. Used for:
/// - KYC tier verification
/// - Accredited investor status
/// - Institutional qualification
///
/// The credential is a signed attestation from a provider. The circuit
/// verifies the structure and checks expiry without revealing the
/// credential contents.
///
/// Public inputs:
///   - provider_id: which provider issued the credential
///   - credential_type: what kind of credential (KYC tier, accreditation, etc.)
///   - is_valid: boolean result
///   - merkle_root: root of authorized providers tree
///   - current_timestamp: for expiry checking
///   - submitter: address of the authorized proof submitter (anti-frontrun)
///
/// Private inputs:
///   - credential_hash: hash of the full credential
///   - expiry_timestamp: when the credential expires
///   - provider_merkle_index: provider's position in the authorized tree
///   - provider_merkle_path: Merkle proof that provider is authorized

use xochi_shared::{compute_merkle_root, hash2, hash3};

/// Credential types (2 and 3 are reserved for future use, e.g. KYC Enhanced, Accredited Investor)
global CREDENTIAL_KYC_BASIC: u8 = 1;
global CREDENTIAL_INSTITUTIONAL: u8 = 4;

fn main(
    // --- Private ---
    credential_hash: Field,
    credential_subject: Field,         // hash of the subject's identity
    credential_attribute: Field,       // hash of the credential attribute value
    expiry_timestamp: u64,
    provider_merkle_index: Field,
    provider_merkle_path: [Field; 20], // MERKLE_DEPTH = 20

    // --- Public ---
    provider_id: pub Field,
    credential_type: pub u8,
    is_valid: pub bool,
    merkle_root: pub Field,            // root of authorized providers tree
    current_timestamp: pub u64,
    submitter: pub Field,               // authorized submitter address (oracle enforces == msg.sender)
) {
    // 0. Anchor submitter as a public input (oracle enforces submitter == msg.sender).
    assert(submitter != 0, "submitter must be non-zero");

    // 1. Verify the credential hash is correctly formed
    let computed_credential_hash = hash_credential(
        provider_id,
        credential_subject,
        credential_type,
        credential_attribute,
        expiry_timestamp,
    );
    assert(computed_credential_hash == credential_hash, "Credential hash mismatch");

    // 2. Verify the provider is in the authorized providers Merkle tree
    let computed_root = compute_merkle_root(
        provider_id,
        provider_merkle_index,
        provider_merkle_path,
    );
    assert(computed_root == merkle_root, "Provider not in authorized set");

    // 3. Check credential expiry
    let not_expired = current_timestamp < expiry_timestamp;

    // 4. Validate credential type
    let valid_type = (credential_type >= CREDENTIAL_KYC_BASIC)
        & (credential_type <= CREDENTIAL_INSTITUTIONAL);

    // 5. The is_valid output must match our computation
    let computed_valid = not_expired & valid_type;
    assert(computed_valid == is_valid, "Validity result mismatch");
}

/// Compute the credential hash from its components.
/// Uses two-round hashing because Noir's Pedersen hash takes fixed-arity inputs.
/// Round 1: hash(provider_id, subject, credential_type) -- identity fields
/// Round 2: hash(attribute, expiry) -- attribute fields
/// Final:   hash(round1, round2) -- combine both halves
fn hash_credential(
    provider_id: Field,
    subject: Field,
    credential_type: u8,
    attribute: Field,
    expiry: u64,
) -> Field {
    // Hash in two rounds to avoid large input arrays
    let h1 = hash3(provider_id, subject, credential_type as Field);
    let h2 = hash2(attribute, expiry as Field);
    hash2(h1, h2)
}

#[test]
fn test_valid_credential() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000; // far future
    let current: u64 = 1700000000;

    let _hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    // Credential should be valid (not expired, valid type)
    let not_expired = current < expiry;
    let valid_type = (cred_type >= CREDENTIAL_KYC_BASIC) & (cred_type <= CREDENTIAL_INSTITUTIONAL);
    assert(not_expired & valid_type);
}

#[test]
fn test_expired_credential() {
    let expiry: u64 = 1600000000;
    let current: u64 = 1700000000;
    assert(current >= expiry); // expired
}

#[test]
fn test_credential_hash_deterministic() {
    let h1 = hash_credential(1, 2, 1, 3, 1000);
    let h2 = hash_credential(1, 2, 1, 3, 1000);
    assert(h1 == h2);
}

#[test]
fn test_credential_hash_different_inputs() {
    let h1 = hash_credential(1, 2, 1, 3, 1000);
    let h2 = hash_credential(1, 2, 2, 3, 1000); // different type
    assert(h1 != h2);
}

#[test]
fn test_main_valid_credential() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    // Build Merkle proof for provider in authorized set (index 0, all-zero siblings)
    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,    // merkle index
        path,
        provider_id,
        cred_type,
        true,   // is_valid
        root,
        current,
        0xdead, // submitter
    );
}

#[test]
fn test_main_expired_credential() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 1600000000;
    let current: u64 = 1700000000;  // after expiry

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,
        path,
        provider_id,
        cred_type,
        false,  // expired -> not valid
        root,
        current,
        0xdead,
    );
}

#[test]
fn test_credential_type_zero_invalid() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = 0;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,
        path,
        provider_id,
        cred_type,
        false,
        root,
        current,
        0xdead,
    );
}

#[test]
fn test_credential_type_above_max_invalid() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = 5;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,
        path,
        provider_id,
        cred_type,
        false,
        root,
        current,
        0xdead,
    );
}

#[test]
fn test_credential_type_boundary_institutional() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = CREDENTIAL_INSTITUTIONAL;
    let attribute: Field = 999;
    let expiry: u64 = 2000000000;
    let current: u64 = 1700000000;

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,
        path,
        provider_id,
        cred_type,
        true,
        root,
        current,
        0xdead,
    );
}

#[test]
fn test_expiry_exact_boundary() {
    let provider_id: Field = 42;
    let subject: Field = 123;
    let cred_type: u8 = CREDENTIAL_KYC_BASIC;
    let attribute: Field = 999;
    let expiry: u64 = 1700000000;
    let current: u64 = 1700000000;

    let credential_hash = hash_credential(provider_id, subject, cred_type, attribute, expiry);

    let path: [Field; 20] = [0; 20];
    let root = compute_merkle_root(provider_id, 0, path);

    main(
        credential_hash,
        subject,
        attribute,
        expiry,
        0,
        path,
        provider_id,
        cred_type,
        false,
        root,
        current,
        0xdead,
    );
}
