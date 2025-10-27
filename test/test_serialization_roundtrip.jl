# test/test_serialization_roundtrip.jl
# Comprehensive serialization roundtrip tests for optimized codec

using Test
using JAM
using StaticArrays

include("../src/crypto/hash.jl")
include("../src/serialization/codec.jl")
include("../src/serialization/decoder.jl")
include("../src/serialization/complex.jl")
include("../src/serialization/jam_types.jl")

@testset "Serialization Roundtrip Tests" begin

    @testset "Writer/Reader Pattern Correctness" begin
        # Test Writer pattern
        writer = Codec.Writer(100)
        Codec.write_u32!(writer, 0x12345678)
        Codec.write_u64!(writer, 0x123456789abcdef0)
        result = Codec.finalize_writer(writer)

        @test length(result) == 12
        @test result[1:4] == [0x78, 0x56, 0x34, 0x12]
        @test result[5:12] == [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]

        # Test Reader pattern
        reader = Decoder.Reader(result, 1)
        @test Decoder.read_u32(reader) == 0x12345678
        @test Decoder.read_u64(reader) == 0x123456789abcdef0
    end

    @testset "Natural Encoding Roundtrip" begin
        test_values = [
            0, 1, 2, 127, 128, 129, 255, 256,
            16383, 16384, 16385, 65535, 65536,
            2097151, 2097152, 1_000_000,
            100_000_000, UInt64(2^32 - 1), UInt64(1) << 40
        ]

        for val in test_values
            # Test old encode
            encoded = Codec.encode(val)
            decoded, _ = Decoder.decode_natural(encoded)
            @test decoded == val

            # Test Writer pattern
            size = Codec.size_of_natural(val)
            writer = Codec.Writer(size)
            Codec.write_natural!(writer, val)
            result = Codec.finalize_writer(writer)

            @test length(result) == length(encoded)
            @test result == encoded

            reader = Decoder.Reader(result, 1)
            decoded2 = Decoder.read_natural(reader)
            @test decoded2 == val
        end
    end

    @testset "Hash Encoding Roundtrip" begin
        # Test various hash values
        test_hashes = [
            zeros(UInt8, 32),
            ones(UInt8, 32),
            fill(0xaa, 32),
            rand(UInt8, 32),
            rand(UInt8, 32),
            rand(UInt8, 32)
        ]

        for hash_vec in test_hashes
            hash_static = SVector{32, UInt8}(hash_vec)

            # Test encode
            encoded = JAMCodec.encode(hash_static)
            @test length(encoded) == 32
            @test encoded == hash_vec

            # Test Writer pattern
            writer = Codec.Writer(32)
            Codec.write_hash!(writer, hash_static)
            result = Codec.finalize_writer(writer)
            @test result == hash_vec

            # Test Reader
            reader = Decoder.Reader(Vector{UInt8}(result), 1)
            decoded = Decoder.read_hash(reader)
            @test decoded == hash_static

            # Test view-based reading (zero-copy)
            reader2 = Decoder.Reader(Vector{UInt8}(result), 1)
            view = Decoder.read_hash_view(reader2)
            @test collect(view) == hash_vec
        end
    end

    @testset "Blob Encoding Roundtrip" begin
        test_blobs = [
            UInt8[],
            [0x01],
            [0x01, 0x02, 0x03],
            rand(UInt8, 100),
            rand(UInt8, 1000),
            rand(UInt8, 10000)
        ]

        for blob in test_blobs
            # Test Writer pattern
            size = Codec.size_of_natural(length(blob)) + length(blob)
            writer = Codec.Writer(size)
            Codec.write_blob!(writer, blob)
            result = Codec.finalize_writer(writer)

            # Test Reader
            reader = Decoder.Reader(result, 1)
            decoded = Decoder.read_blob(reader)
            @test decoded == blob

            # Test view-based reading (zero-copy)
            reader2 = Decoder.Reader(result, 1)
            view = Decoder.read_blob_view(reader2)
            @test collect(view) == blob
        end
    end

    @testset "Complex Type Roundtrip" begin
        # Test encode_with_item_lengths (optimized function)
        test_sequences = [
            Vector{UInt8}[],
            [UInt8[0x01]],
            [UInt8[0x01], UInt8[0x02, 0x03]],
            [rand(UInt8, 10), rand(UInt8, 20), rand(UInt8, 30)]
        ]

        for seq in test_sequences
            encoded = ComplexCodec.encode_with_item_lengths(seq)

            # Verify structure
            reader = Decoder.Reader(encoded, 1)
            count = Decoder.read_natural(reader)
            @test count == length(seq)

            decoded_seq = Vector{Vector{UInt8}}()
            for i in 1:count
                item = Decoder.read_blob(reader)
                push!(decoded_seq, item)
            end

            @test length(decoded_seq) == length(seq)
            for (orig, dec) in zip(seq, decoded_seq)
                @test orig == dec
            end
        end
    end

    @testset "Work Error Encoding" begin
        errors = [:out_of_gas, :panic, :bad_export_count, :bad_import, :bad_code, :code_too_large]
        expected = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]

        for (err, exp) in zip(errors, expected)
            encoded = JAMCodec.encode_error(err)
            @test length(encoded) == 1
            @test encoded[1] == exp
        end
    end

    @testset "Work Result Encoding" begin
        # Error result
        error_result = :out_of_gas
        encoded = JAMCodec.encode_work_result(error_result)
        @test encoded == [0x01]

        # Success result
        success_result = rand(UInt8, 50)
        encoded = JAMCodec.encode_work_result(success_result)
        @test encoded[1] == 0x00  # success marker

        reader = Decoder.Reader(encoded[2:end], 1)
        decoded_len = Decoder.read_natural(reader)
        @test decoded_len == 50
    end

    @testset "Size Calculation Accuracy" begin
        # Test that size calculations are accurate

        # Test size_of_natural
        test_vals = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, UInt64(2^32)]
        for val in test_vals
            expected_size = length(Codec.encode(val))
            calculated_size = Codec.size_of_natural(val)
            @test calculated_size == expected_size
        end
    end
end

println("Serialization roundtrip tests completed!")
