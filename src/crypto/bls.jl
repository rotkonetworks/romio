# src/crypto/bls.jl
# bls signatures for jam validators using blst library

module BLS
using StaticArrays

const libblst = joinpath(@__DIR__, "../../deps/libblst.so")

function __init__()
    if !isfile(libblst)
        error("libblst.so not found at $libblst")
    end
end

const BlsSecretKey = SVector{32, UInt8}
const BlsPublicKey = SVector{144, UInt8}  
const BlsSignature = SVector{96, UInt8}

const JAM_BEEFY_DST = b"$jam_beefy"

function keygen(seed::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::BlsSecretKey
    seed_bytes = collect(UInt8, seed)
    sk = zeros(UInt8, 32)
    ccall((:blst_keygen, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
          sk, seed_bytes, length(seed_bytes), C_NULL, 0)
    return BlsSecretKey(sk)
end

function sk_to_pk(sk::BlsSecretKey)::BlsPublicKey
    # allocate p1 structure (3 * 48 = 144 bytes for projective coords)
    pk_p1 = zeros(UInt8, 144)
    sk_bytes = collect(sk)
    
    ccall((:blst_sk_to_pk_in_g1, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          pk_p1, sk_bytes)
    
    # compress and store
    pk_compressed = zeros(UInt8, 48)
    ccall((:blst_p1_compress, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          pk_compressed, pk_p1)
    
    # jam format - store compressed in first 48 bytes
    pk_full = zeros(UInt8, 144)
    pk_full[1:48] = pk_compressed
    
    return BlsPublicKey(pk_full)
end

function sign_beefy(sk::BlsSecretKey, msg::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::BlsSignature
    msg_bytes = collect(UInt8, msg)
    sk_bytes = collect(sk)
    
    # allocate p2 structure (3 * 96 = 288 bytes for projective)
    hash_p2 = zeros(UInt8, 288)
    sig_p2 = zeros(UInt8, 288)
    
    # hash message to g2 point
    ccall((:blst_hash_to_g2, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
          hash_p2, msg_bytes, length(msg_bytes),
          JAM_BEEFY_DST, length(JAM_BEEFY_DST), C_NULL, 0)
    
    # sign (multiply by secret key)
    ccall((:blst_sign_pk_in_g1, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
          sig_p2, hash_p2, sk_bytes)
    
    # compress to 96 bytes
    sig_compressed = zeros(UInt8, 96)
    ccall((:blst_p2_compress, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          sig_compressed, sig_p2)
    
    return BlsSignature(sig_compressed)
end

function verify_beefy(pk::BlsPublicKey, sig::BlsSignature, msg::Union{Vector{UInt8}, Base.CodeUnits{UInt8, String}})::Bool
    msg_bytes = collect(UInt8, msg)
    pk_bytes = collect(pk)
    sig_bytes = collect(sig)
    
    # extract compressed public key
    pk_compressed = pk_bytes[1:48]
    
    # decompress to affine points
    pk_affine = zeros(UInt8, 96)
    if ccall((:blst_p1_uncompress, libblst), Cint,
             (Ptr{UInt8}, Ptr{UInt8}),
             pk_affine, pk_compressed) != 0
        return false
    end
    
    sig_affine = zeros(UInt8, 192)
    if ccall((:blst_p2_uncompress, libblst), Cint,
             (Ptr{UInt8}, Ptr{UInt8}),
             sig_affine, sig_bytes) != 0
        return false
    end
    
    # verify using core_verify
    result = ccall((:blst_core_verify_pk_in_g1, libblst), Cint,
                   (Ptr{UInt8}, Ptr{UInt8}, Cint,
                    Ptr{UInt8}, Csize_t,
                    Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
                   pk_affine, sig_affine, 1,
                   msg_bytes, length(msg_bytes),
                   JAM_BEEFY_DST, length(JAM_BEEFY_DST), C_NULL, 0)
    
    return result == 0
end

export BlsSecretKey, BlsPublicKey, BlsSignature
export keygen, sk_to_pk, sign_beefy, verify_beefy

end # module
