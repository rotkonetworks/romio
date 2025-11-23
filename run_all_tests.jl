push!(LOAD_PATH, joinpath(@__DIR__, "src"))
include("src/stf/accumulate.jl")

test_dir = "jam-test-vectors/stf/accumulate/full"
tests = readdir(test_dir)
tests = filter(t -> endswith(t, ".json"), tests)
sort!(tests)

passed = 0
failed = 0

for test in tests
    path = joinpath(test_dir, test)
    try
        result = run_accumulate_test_vector(path)
        if result
            global passed += 1
        else
            global failed += 1
        end
    catch e
        println("ERROR in $test: $e")
        global failed += 1
    end
end

println("\n=== FINAL SUMMARY ===")
println("Passed: $passed / $(passed + failed)")
println("Failed: $failed")
