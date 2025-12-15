# JIP-5: Secret key derivation
# Standard method for deriving validator secret keys from a 32-byte seed

module KeyDerivation

using SHA  # for fallback if Blake2b unavailable

# Try to import Blake2b
const BLAKE2B_AVAILABLE = Ref{Bool}(false)
const blake2b_func = Ref{Any}(nothing)

function __init__()
    try
        # Try to load Blake2b from parent module
        Main.JAM.Blake2b
        BLAKE2B_AVAILABLE[] = true
        blake2b_func[] = Main.JAM.Blake2b.blake2b
    catch
        BLAKE2B_AVAILABLE[] = false
    end
end

"""
    blake2b_32(data::Vector{UInt8}) -> Vector{UInt8}

BLAKE2b hash with 32-byte output. Uses libsodium if available, falls back to pure Julia.
"""
function blake2b_32(data::Vector{UInt8})::Vector{UInt8}
    if BLAKE2B_AVAILABLE[] && blake2b_func[] !== nothing
        return blake2b_func[](data, 32)
    end

    # Fallback: use libsodium directly
    try
        lib = Libdl.dlopen("libsodium")
        out = zeros(UInt8, 32)
        ret = ccall(
            Libdl.dlsym(lib, :crypto_generichash),
            Cint,
            (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Culonglong, Ptr{Nothing}, Csize_t),
            out, 32, data, length(data), C_NULL, 0
        )
        Libdl.dlclose(lib)
        if ret == 0
            return out
        end
    catch
    end

    # Final fallback: SHA-256 (NOT cryptographically equivalent, for testing only)
    @warn "Using SHA-256 fallback - NOT production safe"
    return sha256(data)
end

# JIP-5 domain separators (ASCII, no terminator)
const ED25519_DOMAIN = Vector{UInt8}("jam_val_key_ed25519")
const BANDERSNATCH_DOMAIN = Vector{UInt8}("jam_val_key_bandersnatch")

"""
    derive_ed25519_seed(seed::Vector{UInt8}) -> Vector{UInt8}

Derive Ed25519 secret seed from 32-byte master seed using JIP-5.

    ed25519_secret_seed = blake2b("jam_val_key_ed25519" ++ seed)
"""
function derive_ed25519_seed(seed::Vector{UInt8})::Vector{UInt8}
    @assert length(seed) == 32 "Seed must be 32 bytes"
    return blake2b_32(vcat(ED25519_DOMAIN, seed))
end

"""
    derive_bandersnatch_seed(seed::Vector{UInt8}) -> Vector{UInt8}

Derive Bandersnatch secret seed from 32-byte master seed using JIP-5.

    bandersnatch_secret_seed = blake2b("jam_val_key_bandersnatch" ++ seed)
"""
function derive_bandersnatch_seed(seed::Vector{UInt8})::Vector{UInt8}
    @assert length(seed) == 32 "Seed must be 32 bytes"
    return blake2b_32(vcat(BANDERSNATCH_DOMAIN, seed))
end

"""
    trivial_seed(i::UInt32) -> Vector{UInt8}

Generate a trivial 32-byte seed from a 32-bit unsigned integer (for testing only).

    trivial_seed(i) = repeat_8_times(encode_as_32bit_le(i))
"""
function trivial_seed(i::UInt32)::Vector{UInt8}
    le_bytes = reinterpret(UInt8, [i])  # 4 bytes little-endian
    return repeat(le_bytes, 8)           # 32 bytes total
end

trivial_seed(i::Int) = trivial_seed(UInt32(i))

"""
    derive_validator_keys(seed::Vector{UInt8}) -> NamedTuple

Derive both Ed25519 and Bandersnatch secret seeds from master seed.
Returns (ed25519_seed=..., bandersnatch_seed=...)
"""
function derive_validator_keys(seed::Vector{UInt8})
    return (
        ed25519_seed = derive_ed25519_seed(seed),
        bandersnatch_seed = derive_bandersnatch_seed(seed)
    )
end

# Export functions
export derive_ed25519_seed, derive_bandersnatch_seed, trivial_seed, derive_validator_keys

end # module KeyDerivation
