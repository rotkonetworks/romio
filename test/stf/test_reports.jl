# Test reports state transition function

include("../../src/stf/reports.jl")

println("=== Reports STF Test Suite ===\n")

# Test vectors directory
vectors_dir = "jam-test-vectors/stf/reports/tiny"

# Get all test vectors
test_vectors = filter(f -> endswith(f, ".json"), readdir(vectors_dir))

global passed = 0
global failed = 0

for test_file in sort(test_vectors)
    filepath = joinpath(vectors_dir, test_file)

    try
        result = run_reports_test_vector(filepath)
        global passed, failed
        if result
            passed += 1
        else
            failed += 1
        end
    catch e
        println("\n  Exception running $test_file:")
        println("   $e")
        global failed
        failed += 1
    end

    println()
end

# Summary
println("=== Test Summary ===")
println("Passed: $passed")
println("Failed: $failed")
println("Total:  $(passed + failed)")

if failed == 0
    println("\n  All reports tests passed!")
else
    println("\n  Some tests failed")
end
