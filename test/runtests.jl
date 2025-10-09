using Test

# include test modules
include("test_hash.jl")
include("test_codec.jl")
include("test_bls.jl")
include("test_transitions.jl")

println("Running all JAMit tests...")
println("=" ^ 50)

@testset "JAMit Complete Test Suite" begin
    # run all test modules
    @testset "Hashing Tests" begin
        include("test_hash.jl")
    end

    @testset "Codec Tests" begin
        include("test_codec.jl")
    end

    @testset "BLS Tests" begin
        include("test_bls.jl")
    end

    @testset "State Transition Tests" begin
        include("test_transitions.jl")
    end
end

println("\n" * "=" ^ 50)
println("All tests completed!")
println("=" ^ 50)
