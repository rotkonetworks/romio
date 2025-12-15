# Bandersnatch VRF Native Bindings
# Uses Rust FFI via libbandersnatch_ffi

module Bandersnatch

using Libdl

# Path to the native library
const LIB_PATH = joinpath(@__DIR__, "..", "..", "deps", "bandersnatch-ffi", "target", "release", "libbandersnatch_ffi")

# Load library lazily
const _lib = Ref{Ptr{Cvoid}}(C_NULL)

function get_lib()
    if _lib[] == C_NULL
        _lib[] = Libdl.dlopen(LIB_PATH)
    end
    return _lib[]
end

"""
    compute_ticket_id(vrf_output::Vector{UInt8}) -> Vector{UInt8}

Compute ticket ID from a 32-byte VRF output point.
Returns 32-byte ticket ID hash.
"""
function compute_ticket_id(vrf_output::Vector{UInt8})::Vector{UInt8}
    @assert length(vrf_output) >= 32 "VRF output must be at least 32 bytes"

    ticket_id = Vector{UInt8}(undef, 32)

    func = Libdl.dlsym(get_lib(), :bandersnatch_compute_ticket_id)
    result = ccall(func, Cint, (Ptr{UInt8}, Ptr{UInt8}), vrf_output, ticket_id)

    if result != 0
        error("Failed to compute ticket ID: error code $result")
    end

    return ticket_id
end

"""
    compute_ticket_id_from_signature(signature::Vector{UInt8}) -> Vector{UInt8}

Compute ticket ID from a ring VRF signature.
The VRF output is the first 32 bytes of the signature.
Returns 32-byte ticket ID hash.
"""
function compute_ticket_id_from_signature(signature::Vector{UInt8})::Vector{UInt8}
    return compute_ticket_id(signature[1:32])
end

# Ring Verifier handle type
mutable struct RingVerifier
    handle::Ptr{Cvoid}

    function RingVerifier(commitment::Vector{UInt8}, ring_size::Int)
        func = Libdl.dlsym(get_lib(), :bandersnatch_ring_verifier_new)
        handle = ccall(func, Ptr{Cvoid},
            (Ptr{UInt8}, Csize_t, Csize_t),
            commitment, length(commitment), ring_size)

        if handle == C_NULL
            error("Failed to create ring verifier: invalid commitment or ring size")
        end

        v = new(handle)
        finalizer(v) do x
            if x.handle != C_NULL
                free_func = Libdl.dlsym(get_lib(), :bandersnatch_ring_verifier_free)
                ccall(free_func, Cvoid, (Ptr{Cvoid},), x.handle)
                x.handle = C_NULL
            end
        end
        return v
    end
end

"""
    verify(verifier::RingVerifier, data::Vector{UInt8}, signature::Vector{UInt8}) -> (Bool, Union{Vector{UInt8}, Nothing})

Verify a ring VRF signature.
Returns (is_valid, ticket_id) where ticket_id is computed on valid signatures.
"""
function verify(verifier::RingVerifier, data::Vector{UInt8}, signature::Vector{UInt8})
    ticket_id = Vector{UInt8}(undef, 32)

    func = Libdl.dlsym(get_lib(), :bandersnatch_ring_verify)
    result = ccall(func, Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        verifier.handle, data, length(data), signature, length(signature), ticket_id)

    if result == 0
        return (true, ticket_id)
    else
        return (false, nothing)
    end
end

"""
    verify_ticket(gamma_z::Vector{UInt8}, ring_size::Int, entropy::Vector{UInt8},
                  attempt::Int, signature::Vector{UInt8}) -> (Bool, Union{Vector{UInt8}, Nothing})

Verify a Safrole ticket ring VRF signature.
Constructs the VRF input as "jam_ticket_seal" + entropy + attempt_byte.
Returns (is_valid, ticket_id).
"""
function verify_ticket(
    gamma_z::Vector{UInt8},
    ring_size::Int,
    entropy::Vector{UInt8},
    attempt::Int,
    signature::Vector{UInt8}
)
    # Construct VRF input data
    data = vcat(
        Vector{UInt8}(b"jam_ticket_seal"),
        entropy,
        UInt8[attempt & 0xFF]
    )

    verifier = RingVerifier(gamma_z, ring_size)
    return verify(verifier, data, signature)
end

"""
    batch_verify_tickets(gamma_z::Vector{UInt8}, ring_size::Int, entropy::Vector{UInt8},
                        tickets::Vector) -> Vector{Tuple{Union{Vector{UInt8}, Nothing}, Bool}}

Verify multiple Safrole tickets in batch.
Each ticket should have :attempt and :signature fields.
Returns array of (ticket_id, is_valid) tuples.
"""
function batch_verify_tickets(
    gamma_z::Vector{UInt8},
    ring_size::Int,
    entropy::Vector{UInt8},
    tickets
)
    verifier = RingVerifier(gamma_z, ring_size)

    results = Vector{Tuple{Union{Vector{UInt8}, Nothing}, Bool}}()

    for t in tickets
        attempt = get(t, :attempt, 0)
        signature = get(t, :signature, UInt8[])

        if isempty(signature)
            push!(results, (nothing, false))
            continue
        end

        # Construct VRF input data
        data = vcat(
            Vector{UInt8}(b"jam_ticket_seal"),
            entropy,
            UInt8[attempt & 0xFF]
        )

        is_valid, ticket_id = verify(verifier, data, signature)
        push!(results, (ticket_id, is_valid))
    end

    return results
end

"""
    compute_ring_commitment(public_keys::Vector{Vector{UInt8}}) -> Vector{UInt8}

Compute ring commitment from an ordered list of public keys.
Each key is a 32-byte compressed Bandersnatch point.
"""
function compute_ring_commitment(public_keys::Vector{Vector{UInt8}})::Vector{UInt8}
    @assert !isempty(public_keys) "Public keys list cannot be empty"

    # Concatenate all keys
    num_keys = length(public_keys)
    keys_data = Vector{UInt8}(undef, num_keys * 32)
    for (i, key) in enumerate(public_keys)
        @assert length(key) == 32 "Each key must be 32 bytes"
        keys_data[(i-1)*32+1 : i*32] = key
    end

    # Allocate output buffer (commitment is typically < 100 bytes)
    commitment = Vector{UInt8}(undef, 256)
    commitment_len = Ref{Csize_t}(256)

    func = Libdl.dlsym(get_lib(), :bandersnatch_compute_ring_commitment)
    result = ccall(func, Cint,
        (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{Csize_t}),
        keys_data, num_keys, commitment, commitment_len)

    if result != 0
        error("Failed to compute ring commitment: error code $result")
    end

    return commitment[1:commitment_len[]]
end

# Check if library is available
function is_available()::Bool
    try
        get_lib()
        return true
    catch
        return false
    end
end

end # module
