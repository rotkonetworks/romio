# test/test_codec.jl
using Test
using JAM
using StaticArrays

# Include codec modules
include("../src/codec/codec.jl")
include("../src/codec/complex.jl")
include("../src/codec/jam_types.jl")
include("../src/codec/decoder.jl")

@testset "JAM Codec Tests" begin
    
    @testset "Basic Natural Encoding" begin
        # Test cases from spec
        @test Codec.encode(0) == [0x00]
        @test Codec.encode(1) == [0x01]
        @test Codec.encode(127) == [0x7f]
        @test Codec.encode(128) == [0x80, 0x80]
        @test Codec.encode(255) == [0x80, 0xff]
        @test Codec.encode(256) == [0x81, 0x00]
        @test Codec.encode(16383) == [0xbf, 0xff]
        @test Codec.encode(16384) == [0xc0, 0x40, 0x00]
        
        # Test round-trip
        for n in [0, 1, 127, 128, 255, 256, 1000, 10000, 100000]
            encoded = Codec.encode(n)
            decoded, _ = Decoder.decode_natural(encoded)
            @test decoded == n
        end
    end
    
    @testset "Fixed-Length Integer Encoding" begin
        # Little-endian encoding
        @test Codec.encode_u8(255) == [0xff]
        @test Codec.encode_u16(0x1234) == [0x34, 0x12]
        @test Codec.encode_u32(0x12345678) == [0x78, 0x56, 0x34, 0x12]
        @test Codec.encode_u64(0x123456789abcdef0) == [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]
    end
    
    @testset "Bit Encoding" begin
        bits = BitVector([true, false, true, true, false, false, false, true])
        encoded = ComplexCodec.encode(bits)
        @test encoded == [0b10001101]  # LSB first
        
        # With length prefix
        encoded_with_len = ComplexCodec.encode_with_length(bits)
        @test encoded_with_len[1] == 0x08  # length 8
        @test encoded_with_len[2] == 0b10001101
    end
    
    @testset "Optional Encoding" begin
        # Nothing encodes as 0x00
        @test ComplexCodec.encode_option(nothing) == [0x00]
        
        # Some value encodes as 0x01 + value
        @test ComplexCodec.encode_option(UInt8(42)) == [0x01, 0x2a]
    end
    
    @testset "Hash Encoding" begin
        h = SVector{32, UInt8}(fill(0x55, 32))
        encoded = JAMCodec.encode(h)
        @test encoded == fill(0x55, 32)
        @test length(encoded) == 32
    end
    
    @testset "Decoder Tests" begin
        # Test decode_natural
        data = [0x00]
        val, offset = Decoder.decode_natural(data)
        @test val == 0
        @test offset == 2
        
        data = [0x7f, 0x00]
        val, offset = Decoder.decode_natural(data)
        @test val == 127
        @test offset == 2
        
        data = [0x80, 0x80, 0x00]
        val, offset = Decoder.decode_natural(data)
        @test val == 128
        @test offset == 3
        
        # Test decode_fixed
        data = [0x78, 0x56, 0x34, 0x12]
        val = Decoder.decode_fixed_u32(data, 1)
        @test val == 0x12345678
        
        # Test decode_hash
        data = fill(0xaa, 32)
        h = Decoder.decode_hash(data, 1)
        @test h == SVector{32, UInt8}(fill(0xaa, 32))
    end
    
    @testset "Complex Types" begin
        # Test sequence with length
        seq = [UInt8(1), UInt8(2), UInt8(3)]
        encoded = ComplexCodec.encode_with_length(seq)
        @test encoded[1] == 0x03  # length
        @test encoded[2:4] == [0x01, 0x02, 0x03]
        
        # Test dictionary (sorted by key)
        dict = Dict(2 => 20, 1 => 10, 3 => 30)
        encoded = ComplexCodec.encode(dict)
        # Should encode as length 3, then sorted pairs
        @test encoded[1] == 0x03
        # Pairs should be (1,10), (2,20), (3,30)
        @test encoded[2:7] == [0x01, 0x0a, 0x02, 0x14, 0x03, 0x1e]
    end
    
    @testset "Error Encoding" begin
        @test JAMCodec.encode_error(:out_of_gas) == [0x01]
        @test JAMCodec.encode_error(:panic) == [0x02]
        @test JAMCodec.encode_error(:bad_export_count) == [0x03]
        @test JAMCodec.encode_error(:bad_import) == [0x04]
        @test JAMCodec.encode_error(:bad_code) == [0x05]
        @test JAMCodec.encode_error(:code_too_large) == [0x06]
    end
    
    @testset "Round-trip Tests" begin
        # Test encoding and decoding various values
        test_values = [
            0, 1, 127, 128, 255, 256, 1000,
            16383, 16384, 65535, 65536,
            1_000_000, 1_000_000_000
        ]
        
        for val in test_values
            encoded = Codec.encode(val)
            decoded, _ = Decoder.decode_natural(encoded)
            @test decoded == val
        end
    end
end

println("Running codec tests...")
