#!/usr/bin/env julia
include("src/stf/accumulate.jl")

# Run one failing test with extra tracing
test_file = "jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json"
println("Tracing execution of: $(basename(test_file))")
run_accumulate_test_vector(test_file)
