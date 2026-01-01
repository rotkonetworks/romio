//! Bandersnatch VRF FFI for Julia
//!
//! Provides C-compatible functions for:
//! - Computing ticket IDs from VRF output points
//! - Verifying ring VRF signatures

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// ABI version for compatibility checks
pub const BANDERSNATCH_FFI_VERSION_MAJOR: u32 = 0;
pub const BANDERSNATCH_FFI_VERSION_MINOR: u32 = 1;
pub const BANDERSNATCH_FFI_VERSION_PATCH: u32 = 0;

/// Get FFI version (major << 16 | minor << 8 | patch)
#[no_mangle]
pub extern "C" fn bandersnatch_version() -> u32 {
    (BANDERSNATCH_FFI_VERSION_MAJOR << 16)
        | (BANDERSNATCH_FFI_VERSION_MINOR << 8)
        | BANDERSNATCH_FFI_VERSION_PATCH
}

// Error codes
pub const BANDERSNATCH_OK: i32 = 0;
pub const BANDERSNATCH_ERR_NULL_PTR: i32 = -1;
pub const BANDERSNATCH_ERR_INVALID_POINT: i32 = -2;
pub const BANDERSNATCH_ERR_INVALID_OUTPUT: i32 = -3;
pub const BANDERSNATCH_ERR_INVALID_PROOF: i32 = -4;
pub const BANDERSNATCH_ERR_VERIFY_FAILED: i32 = -5;
pub const BANDERSNATCH_ERR_INVALID_INPUT: i32 = -6;
use ark_vrf::reexports::ark_serialize;
use ark_vrf::ring::Verifier as VerifierTrait;
use ark_vrf::suites::bandersnatch::{
    AffinePoint, Input, Output, PcsParams, Public, RingCommitment, RingProof, RingProofParams,
    RingVerifier as ArkRingVerifier,
};
use once_cell::sync::OnceCell;
use std::slice;

// Embed SRS parameters (will be downloaded during build)
static SRS_PARAMS: OnceCell<PcsParams> = OnceCell::new();

// SRS file is embedded at compile time
const SRS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/parameters/zcash-srs-2-11-uncompressed.bin"
));

fn get_pcs_params() -> &'static PcsParams {
    SRS_PARAMS.get_or_init(|| {
        PcsParams::deserialize_uncompressed(&SRS[..])
            .expect("Failed to deserialize embedded SRS parameters")
    })
}

/// Compute ticket ID from VRF output point (first 32 bytes of signature)
///
/// # Arguments
/// * `output_ptr` - Pointer to 32-byte VRF output point (compressed)
/// * `ticket_id_ptr` - Pointer to 32-byte buffer for ticket ID output
///
/// # Returns
/// * 0 on success, non-zero on error
#[no_mangle]
pub extern "C" fn bandersnatch_compute_ticket_id(
    output_ptr: *const u8,
    ticket_id_ptr: *mut u8,
) -> i32 {
    if output_ptr.is_null() || ticket_id_ptr.is_null() {
        return BANDERSNATCH_ERR_NULL_PTR;
    }

    let output_bytes = unsafe { slice::from_raw_parts(output_ptr, 32) };
    let ticket_id_out = unsafe { slice::from_raw_parts_mut(ticket_id_ptr, 32) };

    // Deserialize the affine point
    let affine = match AffinePoint::deserialize_compressed(&output_bytes[..]) {
        Ok(p) => p,
        Err(_) => return BANDERSNATCH_ERR_INVALID_POINT,
    };

    // Create Output and compute hash
    let output = Output::from(affine);
    let hash = output.hash();

    // Copy first 32 bytes of hash to output
    ticket_id_out.copy_from_slice(&hash[..32]);

    BANDERSNATCH_OK
}

/// Opaque handle for ring verifier
pub struct RingVerifierHandle {
    verifier: ArkRingVerifier,
}

/// Create a ring verifier from commitment
///
/// # Arguments
/// * `commitment_ptr` - Pointer to serialized ring commitment
/// * `commitment_len` - Length of commitment data
/// * `ring_size` - Number of keys in the ring
///
/// # Returns
/// * Pointer to verifier handle on success, null on error
#[no_mangle]
pub extern "C" fn bandersnatch_ring_verifier_new(
    commitment_ptr: *const u8,
    commitment_len: usize,
    ring_size: usize,
) -> *mut RingVerifierHandle {
    if commitment_ptr.is_null() || ring_size == 0 {
        return std::ptr::null_mut();
    }

    let commitment_bytes = unsafe { slice::from_raw_parts(commitment_ptr, commitment_len) };

    // Deserialize commitment
    let commitment = match RingCommitment::deserialize_compressed(&commitment_bytes[..]) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // Get PCS params and create ring proof params
    let pc_params = get_pcs_params().clone();
    let params = match RingProofParams::from_pcs_params(ring_size, pc_params) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    // Create verifier key from commitment, then create verifier
    let verifier_key = params.verifier_key_from_commitment(commitment);
    let verifier = params.verifier(verifier_key);

    Box::into_raw(Box::new(RingVerifierHandle { verifier }))
}

/// Free a ring verifier handle
#[no_mangle]
pub extern "C" fn bandersnatch_ring_verifier_free(handle: *mut RingVerifierHandle) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
    }
}

/// Verify a ring VRF signature
///
/// # Arguments
/// * `handle` - Verifier handle from bandersnatch_ring_verifier_new
/// * `data_ptr` - VRF input data (e.g., "jam_ticket_seal" + entropy + attempt)
/// * `data_len` - Length of input data
/// * `signature_ptr` - Ring VRF signature (784 bytes: 32 output + 752 proof)
/// * `signature_len` - Length of signature
/// * `ticket_id_ptr` - Optional output buffer for ticket ID (32 bytes), can be null
///
/// # Returns
/// * 0 on success (valid signature), non-zero on error/invalid
#[no_mangle]
pub extern "C" fn bandersnatch_ring_verify(
    handle: *const RingVerifierHandle,
    data_ptr: *const u8,
    data_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
    ticket_id_ptr: *mut u8,
) -> i32 {
    if handle.is_null() || data_ptr.is_null() || signature_ptr.is_null() {
        return BANDERSNATCH_ERR_NULL_PTR;
    }

    if signature_len < 32 {
        return BANDERSNATCH_ERR_INVALID_POINT;
    }

    let handle = unsafe { &*handle };
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let signature = unsafe { slice::from_raw_parts(signature_ptr, signature_len) };

    // Extract VRF output (first 32 bytes) and proof (rest)
    let output_bytes = &signature[..32];
    let proof_bytes = &signature[32..];

    // Deserialize output point
    let affine = match AffinePoint::deserialize_compressed(&output_bytes[..]) {
        Ok(p) => p,
        Err(_) => return BANDERSNATCH_ERR_INVALID_OUTPUT,
    };
    let output = Output::from(affine);

    // Deserialize proof
    let proof = match RingProof::deserialize_compressed(&proof_bytes[..]) {
        Ok(p) => p,
        Err(_) => return BANDERSNATCH_ERR_INVALID_PROOF,
    };

    // Create VRF input from data (hashes to curve point)
    let input = match Input::new(data) {
        Some(i) => i,
        None => return BANDERSNATCH_ERR_INVALID_INPUT,
    };

    // Verify
    let result = Public::verify(input, output.clone(), &[], &proof, &handle.verifier);

    if result.is_err() {
        return BANDERSNATCH_ERR_VERIFY_FAILED;
    }

    // Optionally compute and return ticket ID
    if !ticket_id_ptr.is_null() {
        let ticket_id_out = unsafe { slice::from_raw_parts_mut(ticket_id_ptr, 32) };
        let hash = output.hash();
        ticket_id_out.copy_from_slice(&hash[..32]);
    }

    BANDERSNATCH_OK
}

/// Compute ring commitment from public keys
///
/// # Arguments
/// * `keys_ptr` - Pointer to array of 32-byte public keys (concatenated)
/// * `num_keys` - Number of keys
/// * `commitment_ptr` - Output buffer for commitment
/// * `commitment_len` - Pointer to length (in: buffer size, out: actual size)
///
/// # Returns
/// * 0 on success, non-zero on error
#[no_mangle]
pub extern "C" fn bandersnatch_compute_ring_commitment(
    keys_ptr: *const u8,
    num_keys: usize,
    commitment_ptr: *mut u8,
    commitment_len: *mut usize,
) -> i32 {
    if keys_ptr.is_null() || commitment_ptr.is_null() || commitment_len.is_null() || num_keys == 0 {
        return BANDERSNATCH_ERR_NULL_PTR;
    }

    let keys_data = unsafe { slice::from_raw_parts(keys_ptr, num_keys * 32) };
    let max_len = unsafe { *commitment_len };

    // Parse keys
    let mut parsed_keys = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        let key_bytes = &keys_data[i * 32..(i + 1) * 32];
        let affine = AffinePoint::deserialize_compressed(&key_bytes[..])
            .unwrap_or_else(|_| RingProofParams::padding_point());
        parsed_keys.push(affine);
    }

    // Get PCS params and create ring proof params
    let pc_params = get_pcs_params().clone();
    let params = match RingProofParams::from_pcs_params(num_keys, pc_params) {
        Ok(p) => p,
        Err(_) => return BANDERSNATCH_ERR_INVALID_INPUT,
    };

    // Construct verifier key and get commitment
    let verifier_key = params.verifier_key(&parsed_keys);
    let commitment = verifier_key.commitment();

    // Serialize commitment
    let mut bytes = Vec::new();
    if commitment.serialize_compressed(&mut bytes).is_err() {
        return BANDERSNATCH_ERR_INVALID_OUTPUT;
    }

    if bytes.len() > max_len {
        return BANDERSNATCH_ERR_INVALID_PROOF; // Buffer too small
    }

    let commitment_out = unsafe { slice::from_raw_parts_mut(commitment_ptr, bytes.len()) };
    commitment_out.copy_from_slice(&bytes);
    unsafe {
        *commitment_len = bytes.len();
    }

    BANDERSNATCH_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_id_computation() {
        // Test with a valid (but dummy) output - this will fail with invalid point
        // In real usage, the output comes from a valid signature
        let output = [0u8; 32];
        let mut ticket_id = [0u8; 32];

        // This should fail because zeros is not a valid curve point
        let result = bandersnatch_compute_ticket_id(output.as_ptr(), ticket_id.as_mut_ptr());
        assert_ne!(result, 0);
    }
}
