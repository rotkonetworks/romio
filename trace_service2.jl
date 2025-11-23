push!(LOAD_PATH, joinpath(@__DIR__, "src"))
include("src/stf/accumulate.jl")

test_path = "jam-test-vectors/stf/accumulate/full/work_for_ejected_service-1.json"
println("=== Testing service 2 (passing test) ===")
result = run_accumulate_test_vector(test_path)
println("\nResult: $(result ? "PASS" : "FAIL")")
