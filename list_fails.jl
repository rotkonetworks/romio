#!/usr/bin/env julia
include("src/stf/accumulate.jl")

total = 0
pass = 0
fails = String[]
test_dir = "jam-test-vectors/stf/accumulate/tiny"

for file in sort(readdir(test_dir))
    if endswith(file, ".json")
        global total += 1
        result = try
            run_accumulate_test_vector(joinpath(test_dir, file))
        catch e
            false
        end
        if result
            global pass += 1
        else
            push!(fails, file)
        end
    end
end

println("\n===== SUMMARY: $pass/$total tests passing =====")
println("Failing tests ($(length(fails))):")
for f in fails
    println("  - $f")
end
