# Precompilation execution file for PackageCompiler
# This file exercises common code paths to improve startup time

using JAM

println("Precompilation: exercising JAM module...")

# PVM interpreter precompilation
println("Precompiling PVM interpreter...")
include(joinpath(@__DIR__, "precompile_pvm.jl"))

# Exercise STF code paths for JIT precompilation
let stf_base = "jam-test-vectors/stf"
    # Run one test from each STF module to trigger JIT compilation
    test_files = [
        ("safrole", joinpath(stf_base, "safrole/tiny/enact-epoch-change-with-no-tickets-1.json")),
        ("reports", joinpath(stf_base, "reports/tiny/bad_core_index-1.json")),
        ("authorizations", joinpath(stf_base, "authorizations/tiny/apply_marker_to_pool-1.json")),
        ("assurances", joinpath(stf_base, "assurances/tiny/assurance_for_stale_reports-1.json")),
        ("disputes", joinpath(stf_base, "disputes/tiny/bad_judgment_age-1.json")),
        ("history", joinpath(stf_base, "history/tiny/add_reported_to_recent-1.json")),
        ("statistics", joinpath(stf_base, "statistics/tiny/stats_with_empty_extrinsic-1.json")),
    ]

    for (name, path) in test_files
        if isfile(path)
            try
                redirect_stdout(devnull) do
                    if name == "safrole"
                        include("../src/stf/safrole.jl")
                        run_safrole_test_vector(path)
                    elseif name == "reports"
                        include("../src/stf/reports.jl")
                        run_reports_test_vector(path)
                    elseif name == "authorizations"
                        include("../src/stf/authorizations.jl")
                        run_authorizations_test_vector(path)
                    elseif name == "assurances"
                        include("../src/stf/assurances.jl")
                        run_assurances_test_vector(path)
                    elseif name == "disputes"
                        include("../src/stf/disputes.jl")
                        run_disputes_test_vector(path)
                    elseif name == "history"
                        include("../src/stf/history.jl")
                        run_history_test_vector(path)
                    elseif name == "statistics"
                        include("../src/stf/statistics.jl")
                        run_statistics_test_vector(path)
                    end
                end
                println("  Precompiled: $name")
            catch e
                println("  Skipped $name: $e")
            end
        end
    end
end

println("Precompilation execution complete")
