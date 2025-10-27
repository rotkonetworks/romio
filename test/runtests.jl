using Test

println("Running JAMit Complete Test Suite...")
println("=" ^ 70)

@testset "JAMit Complete Test Suite" begin
    @testset "Core Functionality Tests" begin
        @testset "Hashing Tests" begin
            include("test_hash.jl")
        end

        @testset "Codec Tests" begin
            include("test_codec.jl")
        end

        @testset "BLS Tests" begin
            include("test_bls.jl")
        end
    end

    @testset "Optimization Tests" begin
        @testset "Serialization Roundtrip Tests" begin
            include("test_serialization_roundtrip.jl")
        end

        @testset "Performance Benchmarks" begin
            include("test_performance.jl")
        end

        @testset "Integration Tests" begin
            include("test_integration.jl")
        end
    end

    @testset "State Transition Tests" begin
        include("test_transitions.jl")
    end
end

println("\n" * "=" ^ 70)
println("✅ All tests completed successfully!")
println("=" ^ 70)
