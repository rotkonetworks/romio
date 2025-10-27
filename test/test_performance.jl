# test/test_performance.jl
# Performance benchmarks for optimized codec

using Test
using Printf
using Statistics
using StaticArrays

include("../src/serialization/codec.jl")
include("../src/serialization/complex.jl")

# Benchmark helper
function benchmark(f, args...; iterations=1000, warmup=100)
    # Warmup
    for _ in 1:warmup
        f(args...)
    end

    # Measure
    times = Float64[]
    for _ in 1:iterations
        t0 = time_ns()
        f(args...)
        t1 = time_ns()
        push!(times, (t1 - t0) / 1e6)  # Convert to milliseconds
    end

    return (
        mean = mean(times),
        median = median(times),
        min = minimum(times),
        max = maximum(times),
        std = std(times)
    )
end

@testset "Performance Benchmarks" begin

    println("\n" * "="^70)
    println("PERFORMANCE BENCHMARKS")
    println("="^70)

    @testset "Writer vs Array Append Performance" begin
        # Test data
        test_size = 1000
        u32_data = rand(UInt32, test_size)

        println("\n📊 Writer vs append! (1000 u32 values):")

        # Writer pattern (optimized)
        function encode_with_writer(data)
            writer = Codec.Writer(4 * length(data))
            for val in data
                Codec.write_u32!(writer, val)
            end
            return Codec.finalize_writer(writer)
        end

        # Old append pattern
        function encode_with_append(data)
            result = UInt8[]
            for val in data
                append!(result, Codec.encode_u32(val))
            end
            return result
        end

        writer_stats = benchmark(encode_with_writer, u32_data)
        append_stats = benchmark(encode_with_append, u32_data)

        speedup = append_stats.mean / writer_stats.mean

        @printf("  Writer pattern:  %.3f ms (median: %.3f ms)\n", writer_stats.mean, writer_stats.median)
        @printf("  Append pattern:  %.3f ms (median: %.3f ms)\n", append_stats.mean, append_stats.median)
        @printf("  🚀 Speedup: %.2fx\n", speedup)

        # Verify correctness
        result1 = encode_with_writer(u32_data)
        result2 = encode_with_append(u32_data)
        @test result1 == result2
    end

    @testset "Hash Concatenation Performance" begin
        # Test vcat vs copyto for hash pairs
        hash1 = rand(UInt8, 32)
        hash2 = rand(UInt8, 32)

        println("\n📊 Hash concatenation (2 x 32 bytes):")

        # Old vcat method
        function concat_with_vcat(h1, h2)
            return vcat(h1, h2)
        end

        # New copyto method
        function concat_with_copyto(h1, h2)
            result = Vector{UInt8}(undef, 64)
            copyto!(result, 1, h1, 1, 32)
            copyto!(result, 33, h2, 1, 32)
            return result
        end

        vcat_stats = benchmark(concat_with_vcat, hash1, hash2, iterations=10000)
        copyto_stats = benchmark(concat_with_copyto, hash1, hash2, iterations=10000)

        speedup = vcat_stats.mean / copyto_stats.mean

        @printf("  vcat:     %.4f ms (median: %.4f ms)\n", vcat_stats.mean, vcat_stats.median)
        @printf("  copyto!:  %.4f ms (median: %.4f ms)\n", copyto_stats.mean, copyto_stats.median)
        @printf("  🚀 Speedup: %.2fx\n", speedup)

        # Verify correctness
        result1 = concat_with_vcat(hash1, hash2)
        result2 = concat_with_copyto(hash1, hash2)
        @test result1 == result2
    end

    @testset "Natural Encoding Performance" begin
        test_values = rand(0:1000000, 1000)

        println("\n📊 Natural encoding (1000 random values):")

        # Writer pattern
        function encode_naturals_writer(values)
            total_size = sum(Codec.size_of_natural(v) for v in values)
            writer = Codec.Writer(total_size)
            for val in values
                Codec.write_natural!(writer, val)
            end
            return Codec.finalize_writer(writer)
        end

        # Old pattern
        function encode_naturals_old(values)
            result = UInt8[]
            for val in values
                append!(result, Codec.encode(val))
            end
            return result
        end

        writer_stats = benchmark(encode_naturals_writer, test_values)
        old_stats = benchmark(encode_naturals_old, test_values)

        speedup = old_stats.mean / writer_stats.mean

        @printf("  Writer pattern:  %.3f ms (median: %.3f ms)\n", writer_stats.mean, writer_stats.median)
        @printf("  Old pattern:     %.3f ms (median: %.3f ms)\n", old_stats.mean, old_stats.median)
        @printf("  🚀 Speedup: %.2fx\n", speedup)

        # Verify correctness
        result1 = encode_naturals_writer(test_values)
        result2 = encode_naturals_old(test_values)
        @test result1 == result2
    end

    @testset "Blob Encoding Performance" begin
        test_blobs = [rand(UInt8, 100) for _ in 1:100]

        println("\n📊 Blob sequence encoding (100 blobs × 100 bytes):")

        # Optimized with Writer
        function encode_blobs_optimized(blobs)
            total_size = sum(Codec.size_of_natural(length(b)) + length(b) for b in blobs)
            total_size += Codec.size_of_natural(length(blobs))

            writer = Codec.Writer(total_size)
            Codec.write_natural!(writer, length(blobs))
            for blob in blobs
                Codec.write_blob!(writer, blob)
            end
            return Codec.finalize_writer(writer)
        end

        # Old pattern with appends
        function encode_blobs_old(blobs)
            result = Codec.encode(length(blobs))
            for blob in blobs
                append!(result, Codec.encode(length(blob)))
                append!(result, blob)
            end
            return result
        end

        optimized_stats = benchmark(encode_blobs_optimized, test_blobs)
        old_stats = benchmark(encode_blobs_old, test_blobs)

        speedup = old_stats.mean / optimized_stats.mean

        @printf("  Optimized:  %.3f ms (median: %.3f ms)\n", optimized_stats.mean, optimized_stats.median)
        @printf("  Old:        %.3f ms (median: %.3f ms)\n", old_stats.mean, old_stats.median)
        @printf("  🚀 Speedup: %.2fx\n", speedup)

        # Verify correctness
        result1 = encode_blobs_optimized(test_blobs)
        result2 = encode_blobs_old(test_blobs)
        @test result1 == result2
    end

    @testset "Large Reconstruction Performance" begin
        # Simulate availability reconstruction
        segments = [rand(UInt8, 4096) for _ in 1:1000]  # 1000 segments of 4KB

        println("\n📊 Large data reconstruction (1000 × 4KB segments):")

        # Optimized with pre-allocation
        function reconstruct_optimized(segs)
            total_size = sum(length(s) for s in segs)
            result = Vector{UInt8}(undef, total_size)
            pos = 1
            for seg in segs
                copyto!(result, pos, seg, 1, length(seg))
                pos += length(seg)
            end
            return result
        end

        # Old with appends
        function reconstruct_old(segs)
            result = UInt8[]
            for seg in segs
                append!(result, seg)
            end
            return result
        end

        optimized_stats = benchmark(reconstruct_optimized, segments, iterations=100)
        old_stats = benchmark(reconstruct_old, segments, iterations=100)

        speedup = old_stats.mean / optimized_stats.mean

        @printf("  Optimized:  %.3f ms (median: %.3f ms)\n", optimized_stats.mean, optimized_stats.median)
        @printf("  Old:        %.3f ms (median: %.3f ms)\n", old_stats.mean, old_stats.median)
        @printf("  🚀 Speedup: %.2fx\n", speedup)

        # Verify correctness
        result1 = reconstruct_optimized(segments)
        result2 = reconstruct_old(segments)
        @test result1 == result2
    end

    println("\n" * "="^70)
    println("Performance benchmarks completed!")
    println("="^70)
end
