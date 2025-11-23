# Simple trace of service 1729 execution
# Just run the accumulate test with tracing enabled

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/stf/accumulate.jl")

# Load test
test_path = "jam-test-vectors/stf/accumulate/full/process_one_immediate_report-1.json"
println("=== Tracing Service 1729 ===")
println("Test: $test_path\n")

# Run the test - tracing will print each step
result = run_accumulate_test_vector(test_path)

println("\n=== Test Result: $(result ? "PASS" : "FAIL") ===")
