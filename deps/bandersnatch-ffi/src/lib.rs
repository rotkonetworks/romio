//! C FFI bindings for Bandersnatch VRF operations
//! Used by JAMit for SAFROLE ticket verification

use ark_vrf::suites::bandersnatch::{Output, Input};
use ark_vrf::ring::{RingProof, RingVerifier, RingCommitment};
use ark_vrf::reexports::ark_serialize::CanonicalDeserialize;
use std::slice;

/// Ring VRF domain size for JAM (1023 validators)
const RING_SIZE: usize = 1023;

/// Compute ticket ID from a ring VRF signature
///
/// # Arguments
/// * `sig_ptr` - Pointer to signature bytes (784 bytes for ring proof)
/// * `sig_len` - Length of signature
/// * `out_ptr` - Pointer to output buffer (32 bytes for ticket ID)
///
/// # Returns
/// * 0 on success
/// * -1 on invalid signature format
/// * -2 on hash computation error
#[no_mangle]
pub extern "C" fn bandersnatch_ticket_id(
    sig_ptr: *const u8,
    sig_len: usize,
    out_ptr: *mut u8,
) -> i32 {
    if sig_ptr.is_null() || out_ptr.is_null() || sig_len < 32 {
        return -1;
    }

    let sig_bytes = unsafe { slice::from_raw_parts(sig_ptr, sig_len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, 32) };

    // Extract VRF output point (first 32 bytes of signature)
    // and compute its hash to get ticket ID
    match Output::deserialize_compressed(&sig_bytes[..32]) {
        Ok(vrf_output) => {
            // Hash the VRF output to get ticket ID
            let hash = vrf_output.hash();
            out.copy_from_slice(&hash[..32]);
            0
        }
        Err(_) => -1,
    }
}

/// Verify a ring VRF signature for a SAFROLE ticket
///
/// # Arguments
/// * `commitment_ptr` - Ring commitment (144 bytes)
/// * `commitment_len` - Length of commitment
/// * `entropy_ptr` - Epoch entropy (32 bytes)
/// * `entropy_len` - Length of entropy
/// * `attempt` - Ticket attempt number (0, 1, or 2)
/// * `sig_ptr` - Ring VRF signature (784 bytes)
/// * `sig_len` - Length of signature
/// * `ticket_id_out` - Output buffer for ticket ID (32 bytes)
///
/// # Returns
/// * 0 on success (valid signature)
/// * -1 on invalid parameters
/// * -2 on verification failure
#[no_mangle]
pub extern "C" fn bandersnatch_ring_verify(
    commitment_ptr: *const u8,
    commitment_len: usize,
    entropy_ptr: *const u8,
    entropy_len: usize,
    attempt: u8,
    sig_ptr: *const u8,
    sig_len: usize,
    ticket_id_out: *mut u8,
) -> i32 {
    if commitment_ptr.is_null() || entropy_ptr.is_null() || sig_ptr.is_null() || ticket_id_out.is_null() {
        return -1;
    }

    if commitment_len != 144 || entropy_len != 32 || sig_len != 784 {
        return -1;
    }

    let commitment = unsafe { slice::from_raw_parts(commitment_ptr, commitment_len) };
    let entropy = unsafe { slice::from_raw_parts(entropy_ptr, entropy_len) };
    let sig = unsafe { slice::from_raw_parts(sig_ptr, sig_len) };
    let out = unsafe { slice::from_raw_parts_mut(ticket_id_out, 32) };

    // Construct VRF input: "jam_ticket_seal" + entropy + attempt
    let mut input_data = Vec::with_capacity(15 + 32 + 1);
    input_data.extend_from_slice(b"jam_ticket_seal");
    input_data.extend_from_slice(entropy);
    input_data.push(attempt);

    // Deserialize ring commitment
    let ring_commitment: RingCommitment = match CanonicalDeserialize::deserialize_compressed(commitment) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    // Create verifier
    let verifier = match RingVerifier::new(ring_commitment, RING_SIZE) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    // Deserialize proof
    let proof: RingProof = match CanonicalDeserialize::deserialize_compressed(sig) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // Create VRF input
    let vrf_input = Input::new(&input_data, &[]);

    // Verify
    match verifier.verify(&vrf_input, &[], &proof) {
        Ok(vrf_output) => {
            // Compute ticket ID from VRF output
            let hash = vrf_output.hash();
            out.copy_from_slice(&hash[..32]);
            0
        }
        Err(_) => -2,
    }
}

/// Get the expected ring proof size in bytes
#[no_mangle]
pub extern "C" fn bandersnatch_ring_proof_size() -> usize {
    784 // Standard ring proof size for JAM
}

/// Get the expected ring commitment size in bytes
#[no_mangle]
pub extern "C" fn bandersnatch_ring_commitment_size() -> usize {
    144 // Ring commitment (gamma_z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sizes() {
        assert_eq!(bandersnatch_ring_proof_size(), 784);
        assert_eq!(bandersnatch_ring_commitment_size(), 144);
    }
}
