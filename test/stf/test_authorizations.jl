# Test authorizations STF

include("../../src/stf/authorizations.jl")
include("../../src/test_vectors/loader.jl")
using JSON3

function main()
    test_dir = "jam-test-vectors/stf/authorizations/tiny"

    # Find all test vectors
    test_files = filter(f -> endswith(f, ".json"), readdir(test_dir))
    sort!(test_files)

    println("\n=== Running Authorizations STF Tests ===\n")

    passed = 0
    failed = 0

    for filename in test_files
        filepath = joinpath(test_dir, filename)
        result = run_authorizations_test_vector(filepath)
        if result
            passed += 1
        else
            failed += 1
        end
    end

    println("\n=== Summary ===")
    println("Passed: $passed")
    println("Failed: $failed")

    return failed == 0
end

# Run if executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    success = main()
    exit(success ? 0 : 1)
end
