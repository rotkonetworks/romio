# Parallel test suite runner
# Leverages all 32 threads of Ryzen 9 7950X3D

using Base.Threads

# Test modules to run
const TEST_MODULES = [
    "test/stf/test_authorizations.jl",
    "test/stf/test_statistics.jl",
    "test/stf/test_history.jl",
    # "test/stf/test_accumulate.jl",  # Commented out - PVM issues
    # "test/stf/test_preimages.jl",    # Add when ready
]

struct TestResult
    module_name::String
    success::Bool
    duration::Float64
end

function run_test_module(test_file::String)::TestResult
    start_time = time()

    # Run test as subprocess to isolate
    cmd = `julia --project=. $test_file`
    success = false

    try
        run(cmd)
        success = true
    catch e
        success = false
    end

    duration = time() - start_time

    return TestResult(test_file, success, duration)
end

function run_all_tests_parallel()
    println("=" ^ 70)
    println("Running JAM Test Suite in Parallel")
    println("Threads available: $(nthreads())")
    println("=" ^ 70)

    # Run all tests in parallel
    results = Vector{TestResult}(undef, length(TEST_MODULES))

    @threads for i in eachindex(TEST_MODULES)
        println("\n[Thread $(threadid())] Starting $(TEST_MODULES[i])...")
        results[i] = run_test_module(TEST_MODULES[i])
        status = results[i].success ? "✅" : "❌"
        println("[Thread $(threadid())] $status $(TEST_MODULES[i]) ($(round(results[i].duration, digits=2))s)")
    end

    # Print summary
    println("\n" * "=" ^ 70)
    println("Test Summary")
    println("=" ^ 70)

    total_passed = 0
    total_failed = 0
    total_duration = 0.0

    for result in results
        status = result.success ? "✅ PASS" : "❌ FAIL"
        println("$status $(result.module_name) ($(round(result.duration, digits=2))s)")

        if result.success
            total_passed += 1
        else
            total_failed += 1
        end
        total_duration = max(total_duration, result.duration)
    end

    println("\n" * "=" ^ 70)
    println("Total: $(total_passed) passed, $(total_failed) failed")
    println("Wall time: $(round(total_duration, digits=2))s (parallel)")
    println("Estimated sequential time: ~$(round(sum(r.duration for r in results), digits=2))s")
    println("Speedup: ~$(round(sum(r.duration for r in results) / total_duration, digits=1))x")
    println("=" ^ 70)

    return total_failed == 0
end

# Run if executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    success = run_all_tests_parallel()
    exit(success ? 0 : 1)
end
