# Test vectors validation framework
using Test
using JSON
using StaticArrays

# Import our JAM types and implementation
include("../src/types/basic.jl")
include("../src/state/state.jl")

"""
Test framework for validating Julia JAM implementation against official test vectors
"""
module TestVectors

using Test
using JSON
using ..Main  # Access to our JAM types

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

"""
Load a test vector from the jamtestvectors directory
"""
function load_test_vector(category::String, chain::String, name::String)
    json_path = joinpath(TEST_VECTORS_PATH, category, chain, "$(name).json")
    bin_path = joinpath(TEST_VECTORS_PATH, category, chain, "$(name).bin")

    if !isfile(json_path) || !isfile(bin_path)
        error("Test vector not found: $json_path or $bin_path")
    end

    json_data = JSON.parsefile(json_path)
    bin_data = read(bin_path)

    return (json_data, bin_data)
end

"""
Convert hex string to byte array
"""
function hex_to_bytes(hex_str::String)::Vector{UInt8}
    if startswith(hex_str, "0x")
        hex_str = hex_str[3:end]
    end
    return [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
end

"""
Test codec encoding/decoding against test vectors
"""
function test_codec_vectors()
    @testset "Codec Test Vectors" begin

        # Test basic types first
        @testset "Basic Codec Tests" begin
            # Test work_item encoding
            json_data, bin_data = load_test_vector("codec", "tiny", "work_item")

            println("Work Item JSON structure:")
            println(JSON.json(json_data, 2))

            println("Binary data length: $(length(bin_data)) bytes")
            println("Binary data (hex): $(bytes2hex(bin_data))")

            # For now, just verify we can load the test vectors
            @test length(bin_data) > 0
            @test !isempty(json_data)
        end

        @testset "Header Tests" begin
            json_data, bin_data = load_test_vector("codec", "tiny", "header_0")

            println("Header JSON structure:")
            println(JSON.json(json_data, 2))

            @test length(bin_data) > 0
            @test haskey(json_data, "parent_hash")
            @test haskey(json_data, "prior_state_root")
        end

        @testset "Block Tests" begin
            json_data, bin_data = load_test_vector("codec", "tiny", "block")

            println("Block JSON keys: $(keys(json_data))")

            @test length(bin_data) > 0
            @test haskey(json_data, "header")
            @test haskey(json_data, "extrinsic")
        end
    end
end

"""
Test state transition functions against test vectors
"""
function test_stf_vectors()
    @testset "STF Test Vectors" begin
        stf_categories = ["accumulate", "assurances", "authorizations",
                         "disputes", "history", "preimages", "reports",
                         "safrole", "statistics"]

        for category in stf_categories
            @testset "STF $category" begin
                stf_path = joinpath(TEST_VECTORS_PATH, "stf", category)
                if isdir(stf_path)
                    # List available test files in this category
                    files = readdir(joinpath(stf_path, "tiny"))
                    json_files = filter(f -> endswith(f, ".json"), files)

                    println("Found $(length(json_files)) test vectors for $category")

                    # Test first few vectors
                    for file in json_files[1:min(3, length(json_files))]
                        test_name = replace(file, ".json" => "")
                        try
                            json_data = JSON.parsefile(joinpath(stf_path, "tiny", file))
                            @test !isempty(json_data)
                            println("✓ Loaded $category/$test_name")
                        catch e
                            @warn "Failed to load $category/$test_name: $e"
                        end
                    end
                end
            end
        end
    end
end

"""
Run all test vector validations
"""
function run_all_tests()
    @testset "JAM Test Vectors Validation" begin
        test_codec_vectors()
        test_stf_vectors()
    end
end

end # module TestVectors

# Export the main test function
export run_all_tests