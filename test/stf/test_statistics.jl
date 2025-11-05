# Test statistics state transition function

include("../../src/stf/statistics.jl")

println("=== Statistics STF Test Suite ===\n")

# Test vectors directory
vectors_dir = "jam-test-vectors/stf/statistics/tiny"

# All statistics test vectors
test_vectors = [
    "stats_with_empty_extrinsic-1.json",
    "stats_with_some_extrinsic-1.json",
    "stats_with_epoch_change-1.json",
]

global passed = 0
global failed = 0

for test_file in test_vectors
    filepath = joinpath(vectors_dir, test_file)

    if !isfile(filepath)
        println("⚠ Test vector not found: $test_file")
        continue
    end

    try
        result = run_statistics_test_vector(filepath)
        global passed, failed
        if result
            passed += 1
        else
            failed += 1
        end
    catch e
        println("\n❌ Exception running $test_file:")
        println("   $e")
        showerror(stdout, e, catch_backtrace())
        println()
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
    println("\n✅ All statistics tests passed!")
else
    println("\n❌ Some tests failed")
end
