# Test accumulate state transition function

include("../../src/stf/accumulate.jl")

println("=== Accumulate STF Test Suite ===\n")

# Test vectors directory
vectors_dir = "jam-test-vectors/stf/accumulate/tiny"

# Get all test vectors sorted alphabetically
all_vectors = sort(filter(f -> endswith(f, ".json"), readdir(vectors_dir)))
println("Found $(length(all_vectors)) test vectors\n")

global passed = 0
global failed = 0
global failed_tests = String[]

for test_file in all_vectors
    filepath = joinpath(vectors_dir, test_file)

    if !isfile(filepath)
        println("⚠ Test vector not found: $test_file")
        continue
    end

    try
        result = run_accumulate_test_vector(filepath)
        global passed, failed, failed_tests
        if result
            passed += 1
        else
            failed += 1
            push!(failed_tests, test_file)
        end
    catch e
        println("\n❌ Exception running $test_file:")
        println("   $(typeof(e)): $e")
        global failed, failed_tests
        failed += 1
        push!(failed_tests, test_file)
    end

    println()
end

# Summary
println("\n" * "="^60)
println("=== Test Summary ===")
println("Passed: $passed")
println("Failed: $failed")
println("Total:  $(passed + failed)")
println("Pass rate: $(round(100 * passed / (passed + failed), digits=1))%")

if length(failed_tests) > 0
    println("\nFailed tests:")
    for t in failed_tests
        println("  - $t")
    end
end

if failed == 0
    println("\n✅ All accumulate tests passed!")
else
    println("\n❌ Some tests failed")
end
