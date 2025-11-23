# Trace a passing test to compare execution

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/stf/accumulate.jl")

# Run passing test
test_path = "jam-test-vectors/stf/accumulate/full/enqueue_self_referential-1.json"
println("=== Tracing Passing Test ===")
println("Test: $test_path\n")

result = run_accumulate_test_vector(test_path)

println("\n=== Test Result: $(result ? "PASS" : "FAIL") ===")
