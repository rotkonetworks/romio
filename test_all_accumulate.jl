#!/usr/bin/env julia
# Run all accumulate test vectors and report results

include("src/stf/accumulate.jl")

test_dir = "jam-test-vectors/stf/accumulate/tiny"
test_files = filter(f -> endswith(f, ".json"), readdir(test_dir, join=true))
sort!(test_files)

println("Running $(length(test_files)) accumulate test vectors...\n")

results = Dict{String, String}()
for test_file in test_files
    name = basename(test_file)
    print("Testing $name... ")
    try
        # Redirect output to suppress test logs
        result = redirect_stdout(devnull) do
            redirect_stderr(devnull) do
                run_accumulate_test_vector(test_file)
            end
        end
        status = result ? "PASS" : "FAIL"
        results[name] = status
        println(status)
    catch e
        results[name] = "ERROR"
        println("ERROR: $(typeof(e))")
    end
end

# Display summary
println("\n" * "="^60)
println("RESULTS")
println("="^60)

passed = String[]
failed = String[]
errors = String[]

for (name, status) in sort(collect(results))
    if status == "PASS"
        push!(passed, name)
    elseif status == "FAIL"
        push!(failed, name)
    else
        push!(errors, name)
    end
end

if !isempty(passed)
    println("\n✅ PASSED ($(length(passed))):")
    for name in passed
        println("   $name")
    end
end

if !isempty(failed)
    println("\n❌ FAILED ($(length(failed))):")
    for name in failed
        println("   $name")
    end
end

if !isempty(errors)
    println("\n⚠️  ERRORS ($(length(errors))):")
    for name in errors
        println("   $name")
    end
end

println("\n" * "="^60)
println("SUMMARY")
println("="^60)
println("Passed: $(length(passed))/$(length(results))")
println("Failed: $(length(failed))/$(length(results))")
println("Errors: $(length(errors))/$(length(results))")
println("Pass rate: $(round(100 * length(passed) / length(results), digits=1))%")
