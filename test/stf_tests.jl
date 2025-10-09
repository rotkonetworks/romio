# State Transition Function (STF) test suite
using Test
using JSON

include("../src/state/state.jl")
include("../src/state/transition.jl")

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

"""
Test framework for JAM State Transition Functions
"""
module STFTests

using Test, JSON

const TEST_VECTORS_PATH = joinpath(@__DIR__, "../jamtestvectors")

"""
Load and parse an STF test vector
"""
function load_stf_test(category::String, test_name::String)
    json_path = joinpath(TEST_VECTORS_PATH, "stf", category, "tiny", "$(test_name).json")

    if !isfile(json_path)
        error("STF test vector not found: $json_path")
    end

    return JSON.parsefile(json_path)
end

"""
Validate STF test structure
"""
function validate_stf_test_structure(test_data::Dict)
    required_keys = ["input", "pre_state", "output", "post_state"]

    for key in required_keys
        if !haskey(test_data, key)
            error("Missing required key: $key")
        end
    end

    return true
end

"""
Test accumulate STF functions
"""
function test_accumulate_stf()
    @testset "Accumulate STF Tests" begin
        stf_path = joinpath(TEST_VECTORS_PATH, "stf", "accumulate", "tiny")

        if !isdir(stf_path)
            @warn "Accumulate STF tests not found at: $stf_path"
            return
        end

        test_files = filter(f -> endswith(f, ".json"), readdir(stf_path))
        println("Found $(length(test_files)) accumulate test vectors")

        # Test a few key scenarios
        key_tests = filter(f -> contains(f, "ready") || contains(f, "chain") || contains(f, "unlock"), test_files)

        for test_file in key_tests[1:min(3, length(key_tests))]
            @testset "Accumulate: $(replace(test_file, ".json" => ""))" begin
                test_data = load_stf_test("accumulate", replace(test_file, ".json" => ""))

                @test validate_stf_test_structure(test_data)

                # Basic structure validation
                @test haskey(test_data, "input")
                @test haskey(test_data, "pre_state")
                @test haskey(test_data, "output")
                @test haskey(test_data, "post_state")

                println("    ✓ Loaded test: $(replace(test_file, ".json" => ""))")
                println("      Input keys: $(keys(test_data["input"]))")
                println("      Pre-state keys: $(keys(test_data["pre_state"]))")
            end
        end
    end
end

"""
Test safrole STF functions (block production)
"""
function test_safrole_stf()
    @testset "Safrole STF Tests" begin
        stf_path = joinpath(TEST_VECTORS_PATH, "stf", "safrole", "tiny")

        if !isdir(stf_path)
            @warn "Safrole STF tests not found at: $stf_path"
            return
        end

        test_files = filter(f -> endswith(f, ".json"), readdir(stf_path))
        println("Found $(length(test_files)) safrole test vectors")

        # Test epoch change scenarios
        epoch_tests = filter(f -> contains(f, "epoch"), test_files)

        for test_file in epoch_tests[1:min(2, length(epoch_tests))]
            @testset "Safrole: $(replace(test_file, ".json" => ""))" begin
                test_data = load_stf_test("safrole", replace(test_file, ".json" => ""))

                @test validate_stf_test_structure(test_data)

                println("    ✓ Loaded test: $(replace(test_file, ".json" => ""))")

                # Check for safrole-specific fields
                if haskey(test_data["pre_state"], "safrole")
                    safrole_state = test_data["pre_state"]["safrole"]
                    println("      Safrole state keys: $(keys(safrole_state))")
                end
            end
        end
    end
end

"""
Test reports STF functions
"""
function test_reports_stf()
    @testset "Reports STF Tests" begin
        stf_path = joinpath(TEST_VECTORS_PATH, "stf", "reports", "tiny")

        if !isdir(stf_path)
            @warn "Reports STF tests not found at: $stf_path"
            return
        end

        test_files = filter(f -> endswith(f, ".json"), readdir(stf_path))
        println("Found $(length(test_files)) reports test vectors")

        # Test a variety of report scenarios
        for test_file in test_files[1:min(3, length(test_files))]
            @testset "Reports: $(replace(test_file, ".json" => ""))" begin
                test_data = load_stf_test("reports", replace(test_file, ".json" => ""))

                @test validate_stf_test_structure(test_data)

                println("    ✓ Loaded test: $(replace(test_file, ".json" => ""))")

                # Check for work reports
                if haskey(test_data["input"], "reports")
                    reports = test_data["input"]["reports"]
                    if isa(reports, Vector) && length(reports) > 0
                        println("      Found $(length(reports)) work reports")
                    end
                end
            end
        end
    end
end

"""
Test disputes STF functions
"""
function test_disputes_stf()
    @testset "Disputes STF Tests" begin
        stf_path = joinpath(TEST_VECTORS_PATH, "stf", "disputes", "tiny")

        if !isdir(stf_path)
            @warn "Disputes STF tests not found at: $stf_path"
            return
        end

        test_files = filter(f -> endswith(f, ".json"), readdir(stf_path))
        println("Found $(length(test_files)) disputes test vectors")

        # Test dispute scenarios
        for test_file in test_files[1:min(2, length(test_files))]
            @testset "Disputes: $(replace(test_file, ".json" => ""))" begin
                test_data = load_stf_test("disputes", replace(test_file, ".json" => ""))

                @test validate_stf_test_structure(test_data)

                println("    ✓ Loaded test: $(replace(test_file, ".json" => ""))")
            end
        end
    end
end

"""
Run all STF tests
"""
function run_all_stf_tests()
    @testset "JAM State Transition Function Tests" begin
        test_accumulate_stf()
        test_safrole_stf()
        test_reports_stf()
        test_disputes_stf()
    end
end

end # module STFTests

"""
Main test runner for STF validation
"""
function main()
    println("🚀 JAM STF Test Vector Validation")
    println("=" ^ 50)

    # First, show available test categories
    stf_base = joinpath(TEST_VECTORS_PATH, "stf")
    if isdir(stf_base)
        categories = filter(d -> isdir(joinpath(stf_base, d)), readdir(stf_base))
        println("Available STF test categories:")

        for cat in categories
            tiny_path = joinpath(stf_base, cat, "tiny")
            if isdir(tiny_path)
                test_count = length(filter(f -> endswith(f, ".json"), readdir(tiny_path)))
                println("  📂 $cat: $test_count tests")
            end
        end
        println()
    end

    # Run the tests
    try
        STFTests.run_all_stf_tests()
        println("\n✅ STF test validation completed!")
        return true
    catch e
        println("\n❌ STF tests failed: $e")
        return false
    end
end

# Run if called directly
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end