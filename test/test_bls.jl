# test/test_bls_working.jl
using Test

libblst_path = joinpath(@__DIR__, "../deps/libblst.so")

@testset "BLS Library Tests" begin
    @testset "Key Generation" begin
        # test with proper IKM (Initial Key Material)
        ikm = collect(UInt8, "this is a proper seed with enough entropy for BLS keygen")
        sk = zeros(UInt8, 32)
        
        ccall((:blst_keygen, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
              sk, ikm, length(ikm), C_NULL, 0)
        
        # secret key should not be all zeros
        @test !all(sk .== 0)
        @test length(sk) == 32
    end
    
    @testset "Public Key Derivation" begin
        # generate a valid secret key
        ikm = collect(UInt8, "test seed for public key derivation with sufficient entropy")
        sk = zeros(UInt8, 32)
        
        ccall((:blst_keygen, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
              sk, ikm, length(ikm), C_NULL, 0)
        
        # derive public key in G1 (96 bytes uncompressed)
        pk_g1 = zeros(UInt8, 96)
        ccall((:blst_sk_to_pk_in_g1, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              pk_g1, sk)
        
        @test !all(pk_g1 .== 0)
        
        # compress to 48 bytes
        pk_compressed = zeros(UInt8, 48)
        ccall((:blst_p1_compress, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              pk_compressed, pk_g1)
        
        @test !all(pk_compressed .== 0)
        @test length(pk_compressed) == 48
        # compressed point should have compression bit set
        @test (pk_compressed[1] & 0x80) != 0
    end
    
    @testset "Sign and Verify" begin
        # generate keypair
        ikm = collect(UInt8, "test key material for signing")
        sk = zeros(UInt8, 32)
        
        ccall((:blst_keygen, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
              sk, ikm, length(ikm), C_NULL, 0)
        
        # public key in G1
        pk_g1 = zeros(UInt8, 96)
        ccall((:blst_sk_to_pk_in_g1, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              pk_g1, sk)
        
        # message to sign
        msg = collect(UInt8, "Test message for BEEFY")
        dst = collect(UInt8, "\$jam_beefy")
        
        # hash message to G2
        msg_point = zeros(UInt8, 192)
        ccall((:blst_hash_to_g2, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
              msg_point, msg, length(msg), dst, length(dst), C_NULL, 0)
        
        # sign (signature in G2)
        sig_g2 = zeros(UInt8, 192)
        ccall((:blst_sign_pk_in_g1, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
              sig_g2, msg_point, sk)
        
        @test !all(sig_g2 .== 0)
        
        # compress signature
        sig_compressed = zeros(UInt8, 96)
        ccall((:blst_p2_compress, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              sig_compressed, sig_g2)
        
        @test !all(sig_compressed .== 0)
        @test length(sig_compressed) == 96
        
        # decompress for verification
        pk_affine = zeros(UInt8, 96)
        pk_compressed = zeros(UInt8, 48)
        ccall((:blst_p1_compress, libblst_path), Cvoid,
              (Ptr{UInt8}, Ptr{UInt8}),
              pk_compressed, pk_g1)
        
        result = ccall((:blst_p1_uncompress, libblst_path), Cint,
                       (Ptr{UInt8}, Ptr{UInt8}),
                       pk_affine, pk_compressed)
        @test result == 0
        
        sig_affine = zeros(UInt8, 192)
        result = ccall((:blst_p2_uncompress, libblst_path), Cint,
                       (Ptr{UInt8}, Ptr{UInt8}),
                       sig_affine, sig_compressed)
        @test result == 0
        
        # verify signature
        verify_result = ccall((:blst_core_verify_pk_in_g1, libblst_path), Cint,
                              (Ptr{UInt8}, Ptr{UInt8}, Cint,
                               Ptr{UInt8}, Csize_t,
                               Ptr{UInt8}, Csize_t, Ptr{Nothing}, Csize_t),
                              pk_affine, sig_affine, 1,
                              msg, length(msg),
                              dst, length(dst), C_NULL, 0)
        
        @test verify_result == 0  # 0 means success
    end
end

println("All BLS tests passed!")
