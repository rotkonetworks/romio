# src/crypto/bls.jl
# bls signatures for jam validators using blst library

module BLS
using StaticArrays

# load the shared library from deps
const libblst = joinpath(@__DIR__, "../../deps/libblst.so")

# check library exists at module load
function __init__()
    if !isfile(libblst)
        error("libblst.so not found at $libblst")
    end
end

# jam spec sizes - 144 bytes for public key per gray paper
const BlsSecretKey = SVector{32, UInt8}
const BlsPublicKey = SVector{144, UInt8}  # jam spec: 144 bytes
const BlsSignature = SVector{96, UInt8}

# domain separation tag for jam beefy
const JAM_BEEFY_DST = b"$jam_beefy"

# generate secret key from seed
function keygen(seed::Vector{UInt8})::BlsSecretKey
    sk = zeros(UInt8, 32)
    ccall((:blst_keygen, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
          sk, seed, length(seed), C_NULL, 0)
    return BlsSecretKey(sk)
end

# derive public key from secret key (jam's 144-byte format)
function sk_to_pk(sk::BlsSecretKey)::BlsPublicKey
    # standard compressed g1 point
    pk_g1_compressed = zeros(UInt8, 48)
    ccall((:blst_sk_to_pk_in_g1, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          pk_g1_compressed, sk)
    
    # uncompressed g1 point (96 bytes)
    pk_g1_uncompressed = zeros(UInt8, 96)
    # decompress g1 point
    p1_affine = zeros(UInt8, 96)
    ccall((:blst_p1_uncompress, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          p1_affine, pk_g1_compressed)
    ccall((:blst_p1_affine_serialize, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}),
          pk_g1_uncompressed, p1_affine)
    
    # jam uses 144 bytes: likely [96 bytes uncompressed g1 | 48 bytes compressed g1]
    # or [48 compressed g1 | 96 compressed g2]
    pk_full = zeros(UInt8, 144)
    pk_full[1:96] = pk_g1_uncompressed
    pk_full[97:144] = pk_g1_compressed
    
    return BlsPublicKey(pk_full)
end

# sign message with secret key for beefy
function sign_beefy(sk::BlsSecretKey, msg::Vector{UInt8})::BlsSignature
    sig = zeros(UInt8, 96)
    # sign in g2 for beefy
    ccall((:blst_sign, libblst), Cvoid,
          (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}, Csize_t, 
           Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
          sig, sk, msg, length(msg), 
          JAM_BEEFY_DST, length(JAM_BEEFY_DST), C_NULL, 0)
    return BlsSignature(sig)
end

# verify signature with public key
function verify_beefy(pk::BlsPublicKey, sig::BlsSignature, msg::Vector{UInt8})::Bool
    # extract compressed g1 from 144-byte key (last 48 bytes based on our packing)
    pk_g1 = @view pk[97:144]
    
    result = ccall((:blst_core_verify_pk_in_g1, libblst), Cint,
                   (Ptr{UInt8}, Ptr{UInt8}, Cint,
                    Ptr{UInt8}, Csize_t, 
                    Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                   pk_g1, sig, 1,
                   msg, length(msg),
                   JAM_BEEFY_DST, length(JAM_BEEFY_DST), C_NULL, 0)
    return result == 0
end

# aggregate multiple signatures for beefy
function aggregate_signatures(sigs::Vector{BlsSignature})::BlsSignature
    if isempty(sigs)
        return BlsSignature(zeros(UInt8, 96))
    end
    
    agg = zeros(UInt8, 96)
    agg .= sigs[1]
    
    for i in 2:length(sigs)
        # aggregate in g2
        p2_affine_agg = zeros(UInt8, 192)
        p2_affine_new = zeros(UInt8, 192)
        
        ccall((:blst_p2_uncompress, libblst), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              p2_affine_agg, agg)
        ccall((:blst_p2_uncompress, libblst), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              p2_affine_new, sigs[i])
        ccall((:blst_p2_add_affine, libblst), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
              p2_affine_agg, p2_affine_agg, p2_affine_new)
        ccall((:blst_p2_compress, libblst), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              agg, p2_affine_agg)
    end
    
    return BlsSignature(agg)
end

# verify aggregated signature for beefy finality proofs
function verify_aggregate(pks::Vector{BlsPublicKey}, 
                         agg_sig::BlsSignature,
                         msg::Vector{UInt8})::Bool
    if isempty(pks)
        return false
    end
    
    # aggregate public keys
    agg_pk = zeros(UInt8, 48)
    for (i, pk) in enumerate(pks)
        pk_g1 = @view pk[97:144]  # extract compressed g1
        if i == 1
            agg_pk .= pk_g1
        else
            p1_affine_agg = zeros(UInt8, 96)
            p1_affine_new = zeros(UInt8, 96)
            
            ccall((:blst_p1_uncompress, libblst), Cvoid,
                  (Ptr{UInt8}, Ptr{UInt8}),
                  p1_affine_agg, agg_pk)
            ccall((:blst_p1_uncompress, libblst), Cvoid,
                  (Ptr{UInt8}, Ptr{UInt8}),
                  p1_affine_new, pk_g1)
            ccall((:blst_p1_add_affine, libblst), Cvoid,
                  (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
                  p1_affine_agg, p1_affine_agg, p1_affine_new)
            ccall((:blst_p1_compress, libblst), Cvoid,
                  (Ptr{UInt8}, Ptr{UInt8}),
                  agg_pk, p1_affine_agg)
        end
    end
    
    # verify aggregated signature
    result = ccall((:blst_core_verify_pk_in_g1, libblst), Cint,
                   (Ptr{UInt8}, Ptr{UInt8}, Cint,
                    Ptr{UInt8}, Csize_t, 
                    Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                   agg_pk, agg_sig, 1,
                   msg, length(msg),
                   JAM_BEEFY_DST, length(JAM_BEEFY_DST), C_NULL, 0)
    return result == 0
end

export BlsSecretKey, BlsPublicKey, BlsSignature
export keygen, sk_to_pk, sign_beefy, verify_beefy
export aggregate_signatures, verify_aggregate

end # module
