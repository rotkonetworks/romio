# Assurances State Transition Function
# Per graypaper section on assurances

include("../types/basic.jl")
include("../test_vectors/loader.jl")
using JSON3

# Parse hex string to bytes
function parse_hex_bytes(hex_str::AbstractString)::Vector{UInt8}
    s = startswith(hex_str, "0x") ? hex_str[3:end] : hex_str
    if length(s) % 2 != 0
        s = "0" * s
    end
    return [parse(UInt8, s[i:i+1], base=16) for i in 1:2:length(s)]
end

# Convert bytes to hex string
function bytes_to_hex(bytes::Vector{UInt8})::String
    return "0x" * join([string(b, base=16, pad=2) for b in bytes])
end

# Blake2b hash (32 byte output) using libsodium
using libsodium_jll

function blake2b_hash(data::Vector{UInt8})::Vector{UInt8}
    out = zeros(UInt8, 32)
    ccall((:crypto_generichash, libsodium), Cint,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Culonglong, Ptr{UInt8}, Csize_t),
        out, 32, data, length(data), C_NULL, 0)
    return out
end

# Native Julia Ed25519 verification using libsodium
include("../crypto/ed25519.jl")

function verify_ed25519_signature(public_key_hex::String, message_hex::String, signature_hex::String)::Bool
    return verify_ed25519_hex(public_key_hex, message_hex, signature_hex)
end

# Signing context for availability assurances (graypaper XA)
const ASSURANCE_SIGNING_CONTEXT = b"jam_available"

# Process assurances STF
# Returns (new_state, result) where result is :ok or error symbol
function process_assurances(
    avail_assignments,
    curr_validators,
    slot::UInt32,
    parent_hash::Hash,
    parent_hash_str::AbstractString,
    assurances
)
    num_cores = length(avail_assignments)
    num_validators = length(curr_validators)

    # First check all validator indices are valid (within bounds)
    for assurance in assurances
        validator_idx = assurance[:validator_index]
        if validator_idx >= num_validators
            return (nothing, :bad_validator_index)
        end
    end

    # Check assurers are sorted and unique by validator_index
    prev_validator_idx = -1
    for assurance in assurances
        validator_idx = assurance[:validator_index]
        if validator_idx <= prev_validator_idx
            return (nothing, :not_sorted_or_unique_assurers)
        end
        prev_validator_idx = validator_idx
    end

    # Validate each assurance
    for assurance in assurances
        validator_idx = assurance[:validator_index]
        signature_hex = assurance[:signature]

        # Check: anchor must match parent hash
        anchor_str = assurance[:anchor]
        if anchor_str != parent_hash_str
            return (nothing, :bad_attestation_parent)
        end

        # Get bitfield - indicates which cores this assurance covers
        bitfield_hex = assurance[:bitfield]
        bitfield_bytes = parse_hex_bytes(bitfield_hex)

        # Verify Ed25519 signature
        # Message format: context || blake2b(anchor || bitfield)
        validator = curr_validators[validator_idx + 1]  # Julia 1-indexed
        public_key_hex = validator[:ed25519]

        # Build message: jam_available ++ H(anchor ++ bitfield)
        anchor_bytes = parse_hex_bytes(anchor_str)
        payload_bytes = vcat(anchor_bytes, bitfield_bytes)
        payload_hash = blake2b_hash(payload_bytes)
        message_bytes = vcat(Vector{UInt8}(ASSURANCE_SIGNING_CONTEXT), payload_hash)
        message_hex = bytes_to_hex(message_bytes)

        if !verify_ed25519_signature(public_key_hex, message_hex, signature_hex)
            return (nothing, :bad_signature)
        end

        # Check each bit in the bitfield - if a bit is set, that core must be engaged
        for (byte_idx, byte) in enumerate(bitfield_bytes)
            for bit_pos in 0:7
                if (byte >> bit_pos) & 0x01 != 0
                    # Core index: byte_idx is 1-indexed, bit_pos is 0-indexed
                    # Bit 0 of byte 1 = core 0, bit 1 of byte 1 = core 1, etc.
                    core_idx = (byte_idx - 1) * 8 + bit_pos

                    # Check: core must exist
                    if core_idx >= num_cores
                        return (nothing, :core_not_engaged)
                    end

                    # Check: core must be engaged (have a work report assigned)
                    # Julia is 1-indexed
                    assignment = avail_assignments[core_idx + 1]
                    if assignment === nothing
                        return (nothing, :core_not_engaged)
                    end
                end
            end
        end
    end

    # If we get here, assurances are valid
    return (avail_assignments, :ok)
end

# Run assurances test vector
function run_assurances_test_vector(filepath::String)
    println("\n=== Running Assurances Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse input
    slot = UInt32(tv[:input][:slot])
    parent_hash_str = tv[:input][:parent]
    parent_hash = parse_hash(parent_hash_str)
    assurances = tv[:input][:assurances]

    # Parse pre-state
    avail_assignments = tv[:pre_state][:avail_assignments]
    curr_validators = tv[:pre_state][:curr_validators]

    println("Input:")
    println("  Slot: $slot")
    println("  Assurances: $(length(assurances))")

    # Run state transition
    result_state, result = process_assurances(
        avail_assignments, curr_validators, slot, parent_hash, parent_hash_str, assurances
    )

    # Check expected output
    expected_output = tv[:output]

    println("\n=== State Comparison ===")

    if haskey(expected_output, :err)
        # Expected an error
        expected_err = Symbol(expected_output[:err])
        if result == expected_err
            println("✅ Correct error returned: $result")
            println("\n=== Test Vector Result ===")
            println("✅ PASS")
            return true
        else
            println("❌ Wrong error: expected $expected_err, got $result")
            println("\n=== Test Vector Result ===")
            println("❌ FAIL")
            return false
        end
    else
        # Expected success
        if result == :ok
            println("✅ Success as expected")
            println("\n=== Test Vector Result ===")
            println("✅ PASS")
            return true
        else
            println("❌ Expected success, got error: $result")
            println("\n=== Test Vector Result ===")
            println("❌ FAIL")
            return false
        end
    end
end

export process_assurances, run_assurances_test_vector
