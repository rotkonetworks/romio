#!/usr/bin/env julia
# Test all accumulate vectors

include("src/stf/accumulate.jl")

test_dir = "jam-test-vectors/stf/accumulate/tiny"
test_files = sort(filter(f -> endswith(f, ".json"), readdir(test_dir, join=true)))

pass_list = String[]
fail_list = String[]

for test_file in test_files
    test_name = basename(test_file)
    try
        result = run_accumulate_test_vector(test_file)
        if result
            push!(pass_list, test_name)
            println("✅ $test_name")
        else
            push!(fail_list, test_name)
            println("❌ $test_name")
        end
    catch e
        push!(fail_list, test_name)
        println("❌ $test_name (exception: $(typeof(e)))")
    end
end

passed = length(pass_list)
failed = length(fail_list)
total = passed + failed

println("\n========================================")
println("FINAL RESULTS: $passed / $total tests passing")
println("Pass rate: $(round(100*passed/total, digits=1))%")
println("========================================")

if passed > 0
    println("\n✅ PASSING TESTS ($passed):")
    for name in pass_list
        println("  - $name")
    end
end

if failed > 0
    println("\n❌ FAILING TESTS ($failed):")
    for name in fail_list
        println("  - $name")
    end
end
