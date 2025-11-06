# Test history state transition function

include("../../src/stf/history.jl")

println("=== History STF Test Suite ===\n")

# Test vectors directory
vectors_dir = "jam-test-vectors/stf/history/tiny"

# All history test vectors
test_vectors = [
    "progress_blocks_history-1.json",
    "progress_blocks_history-2.json",
    "progress_blocks_history-3.json",
    "progress_blocks_history-4.json",
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
        result = run_history_test_vector(filepath)
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
    println("\n✅ All history tests passed!")
else
    println("\n❌ Some tests failed")
end
