# Test accumulate state transition function

include("../../src/stf/accumulate.jl")

println("=== Accumulate STF Test Suite ===\n")

# Test vectors directory
vectors_dir = "jam-test-vectors/stf/accumulate/tiny"

# Start with simplest tests
test_vectors = [
    "no_available_reports-1.json",
    "process_one_immediate_report-1.json",
    "accumulate_ready_queued_reports-1.json",
    "enqueue_and_unlock_simple-1.json",
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
        result = run_accumulate_test_vector(filepath)
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
    println("\n✅ All accumulate tests passed!")
else
    println("\n❌ Some tests failed")
end
