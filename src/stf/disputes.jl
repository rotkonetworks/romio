# Disputes State Transition Function
# Per graypaper section on disputes

include("../types/basic.jl")
include("../test_vectors/loader.jl")
using JSON3

# Process disputes STF
# Returns (offenders_mark, result) where result is :ok or error symbol
function process_disputes(
    kappa,      # validator keys current epoch
    lambda,     # validator keys previous epoch
    psi,        # pending judgements
    rho,        # availability reports
    tau,        # timeslot
    disputes    # input disputes
)
    verdicts = get(disputes, :verdicts, [])
    culprits = get(disputes, :culprits, [])
    faults = get(disputes, :faults, [])

    # 1. Check verdicts are sorted and unique by target
    if length(verdicts) > 1
        prev_target = verdicts[1][:target]
        for i in 2:length(verdicts)
            curr_target = verdicts[i][:target]
            if curr_target <= prev_target
                return (String[], :verdicts_not_sorted_unique)
            end
            prev_target = curr_target
        end
    end

    # 2. Check each verdict's votes (judgements) are sorted and unique by index
    for verdict in verdicts
        votes = get(verdict, :votes, [])
        if length(votes) > 1
            prev_idx = votes[1][:index]
            for i in 2:length(votes)
                curr_idx = votes[i][:index]
                if curr_idx <= prev_idx
                    return (String[], :judgements_not_sorted_unique)
                end
                prev_idx = curr_idx
            end
        end
    end

    # 3. Check culprits are sorted and unique by key
    if length(culprits) > 1
        prev_key = culprits[1][:key]
        for i in 2:length(culprits)
            curr_key = culprits[i][:key]
            if curr_key <= prev_key
                return (String[], :culprits_not_sorted_unique)
            end
            prev_key = curr_key
        end
    end

    # 4. Check faults are sorted and unique by key
    if length(faults) > 1
        prev_key = faults[1][:key]
        for i in 2:length(faults)
            curr_key = faults[i][:key]
            if curr_key <= prev_key
                return (String[], :faults_not_sorted_unique)
            end
            prev_key = curr_key
        end
    end

    # 5. Check verdicts are not already judged
    psi_good = get(psi, :good, [])
    psi_bad = get(psi, :bad, [])
    psi_wonky = get(psi, :wonky, [])
    psi_offenders = get(psi, :offenders, [])
    all_judged = Set{String}()
    for h in psi_good
        push!(all_judged, h)
    end
    for h in psi_bad
        push!(all_judged, h)
    end
    for h in psi_wonky
        push!(all_judged, h)
    end
    for verdict in verdicts
        target = verdict[:target]
        if target in all_judged
            return (String[], :already_judged)
        end
    end

    # 6. Check culprits/faults are not already reported as offenders
    offenders_set = Set(psi_offenders)
    for culprit in culprits
        key = culprit[:key]
        if key in offenders_set
            return (String[], :offender_already_reported)
        end
    end
    for fault in faults
        key = fault[:key]
        if key in offenders_set
            return (String[], :offender_already_reported)
        end
    end

    # 6. Classify verdicts (GOOD, BAD, or WONKY) and validate consistency
    # Vote semantics: true = report is VALID, false = report is INVALID
    # Supermajority: >2/3 votes, so need floor(2n/3) + 1 votes

    verdict_classifications = Dict{String, Symbol}()  # target -> :good, :bad, or :wonky

    for verdict in verdicts
        votes = get(verdict, :votes, [])
        true_votes = count(v -> v[:vote] == true, votes)
        false_votes = count(v -> v[:vote] == false, votes)
        total_votes = length(votes)
        target = verdict[:target]

        # Supermajority threshold: >2/3, so floor(2n/3) + 1
        # With 5 votes: floor(10/3) + 1 = 3 + 1 = 4
        supermajority_threshold = div(2 * total_votes, 3) + 1
        has_valid_supermajority = true_votes >= supermajority_threshold   # report is GOOD
        has_invalid_supermajority = false_votes >= supermajority_threshold # report is BAD

        if has_valid_supermajority
            verdict_classifications[target] = :good
        elseif has_invalid_supermajority
            verdict_classifications[target] = :bad
        else
            # Neither supermajority - WONKY verdict (valid outcome, no offenders)
            verdict_classifications[target] = :wonky
        end
    end

    # Count BAD and GOOD verdicts for culprits/faults requirements
    bad_verdicts = [t for (t, c) in verdict_classifications if c == :bad]
    good_verdicts = [t for (t, c) in verdict_classifications if c == :good]

    # If any BAD verdict exists, need at least 2 culprits
    if !isempty(bad_verdicts) && length(culprits) < 2
        return (String[], :not_enough_culprits)
    end

    # If any GOOD verdict exists, need at least 1 fault
    if !isempty(good_verdicts) && length(faults) < 1
        return (String[], :not_enough_faults)
    end

    # Culprits can only exist for BAD verdicts
    if !isempty(culprits) && isempty(bad_verdicts)
        return (String[], :culprits_verdict_not_bad)
    end

    # Check each culprit references a BAD verdict
    for culprit in culprits
        culprit_target = culprit[:target]
        if get(verdict_classifications, culprit_target, :missing) != :bad
            return (String[], :culprits_verdict_not_bad)
        end
    end

    # Check each fault: must reference a GOOD verdict and have vote=false
    for fault in faults
        fault_target = fault[:target]
        if get(verdict_classifications, fault_target, :missing) != :good
            return (String[], :fault_verdict_wrong)
        end
        # Fault must have voted false (against the GOOD verdict)
        if fault[:vote] == true
            return (String[], :fault_verdict_wrong)
        end
    end

    # Build offenders list from culprits (for BAD verdicts) and faults (for GOOD verdicts)
    offenders = String[]
    for culprit in culprits
        push!(offenders, culprit[:key])
    end
    for fault in faults
        push!(offenders, fault[:key])
    end

    return (offenders, :ok)
end

# Run disputes test vector
function run_disputes_test_vector(filepath::String)
    println("\n=== Running Disputes Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse input
    disputes = tv[:input][:disputes]

    # Parse pre-state
    kappa = tv[:pre_state][:kappa]
    lambda = tv[:pre_state][:lambda]
    psi = tv[:pre_state][:psi]
    rho = tv[:pre_state][:rho]
    tau = tv[:pre_state][:tau]

    println("Input:")
    println("  Disputes: $(length(disputes))")

    # Run state transition
    offenders, result = process_disputes(kappa, lambda, psi, rho, tau, disputes)

    # Check expected output
    expected_output = tv[:output]

    println("\n=== State Comparison ===")

    if haskey(expected_output, :err)
        # Expected an error
        expected_err = Symbol(expected_output[:err])
        if result == expected_err
            println("  Correct error returned: $result")
            println("\n=== Test Vector Result ===")
            println("  PASS")
            return true
        else
            println("  Wrong error: expected $expected_err, got $result")
            println("\n=== Test Vector Result ===")
            println("  FAIL")
            return false
        end
    else
        # Expected success
        if result == :ok
            # Check offenders match
            expected_offenders = expected_output[:ok][:offenders_mark]
            if Set(offenders) == Set(expected_offenders)
                println("  Success as expected")
                println("\n=== Test Vector Result ===")
                println("  PASS")
                return true
            else
                println("  Offenders mismatch")
                println("    Expected: $(length(expected_offenders)) offenders")
                println("    Got: $(length(offenders)) offenders")
                println("\n=== Test Vector Result ===")
                println("  FAIL")
                return false
            end
        else
            println("  Expected success, got error: $result")
            println("\n=== Test Vector Result ===")
            println("  FAIL")
            return false
        end
    end
end

export process_disputes, run_disputes_test_vector
