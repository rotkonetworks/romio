# Disputes State Transition Function
# Per graypaper section on disputes

include("../types/basic.jl")
include("../test_vectors/loader.jl")
include("../crypto/ed25519.jl")
using JSON3

# Epoch length (tiny = 12, full = 600)
const EPOCH_LENGTH_DISPUTES_TINY = 12
const EPOCH_LENGTH_DISPUTES_FULL = 600

# Get epoch length based on validator count
function get_epoch_length_disputes(validator_count::Int)
    return validator_count <= 10 ? EPOCH_LENGTH_DISPUTES_TINY : EPOCH_LENGTH_DISPUTES_FULL
end

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

    # Compute epoch information
    epoch_length = get_epoch_length_disputes(length(kappa))
    current_epoch = div(tau, epoch_length)

    # 5. Validate judgement age
    # Per graypaper and test vectors analysis:
    # - age=0 → use kappa (current epoch validators)
    # - age=current_epoch-1 → use lambda (previous epoch validators)
    # - Any other age value is invalid (bad_judgement_age)
    #
    # Example with epoch=3:
    # - age=0: valid, use kappa
    # - age=2: valid (3-1=2), use lambda
    # - age=1: INVALID (not 0, not epoch-1)
    for verdict in verdicts
        age = get(verdict, :age, 0)
        valid_age_for_lambda = current_epoch > 0 ? current_epoch - 1 : -1
        if age != 0 && age != valid_age_for_lambda
            return (String[], :bad_judgement_age)
        end
    end

    # 6. Validate verdict vote signatures
    for verdict in verdicts
        votes = get(verdict, :votes, [])
        target = verdict[:target]
        age = get(verdict, :age, 0)

        # Select validator set based on age
        # age=0 → kappa (current epoch), age=current_epoch-1 → lambda (previous epoch)
        validators = age == 0 ? kappa : lambda

        for vote in votes
            idx = vote[:index]
            sig_hex = string(vote[:signature])
            vote_value = vote[:vote]

            # Check validator index is valid
            if idx < 0 || idx >= length(validators)
                return (String[], :bad_validator_index)
            end

            # Get validator's Ed25519 public key
            validator = validators[idx + 1]  # 1-indexed in Julia
            pubkey_hex = string(validator[:ed25519])

            # Build message: context || target_hash
            # Context: "jam_valid" for true votes, "jam_invalid" for false votes
            context = vote_value ? "jam_valid" : "jam_invalid"
            target_hex = startswith(target, "0x") ? target[3:end] : target
            message = Vector{UInt8}(context)
            append!(message, hex2bytes(target_hex))

            # Verify signature
            pubkey_bytes = hex2bytes(startswith(pubkey_hex, "0x") ? pubkey_hex[3:end] : pubkey_hex)
            sig_bytes = hex2bytes(startswith(sig_hex, "0x") ? sig_hex[3:end] : sig_hex)

            if !verify_ed25519(pubkey_bytes, message, sig_bytes)
                return (String[], :bad_signature)
            end
        end
    end

    # 7. Extract psi components early for validation
    psi_good = get(psi, :good, [])
    psi_bad = get(psi, :bad, [])
    psi_wonky = get(psi, :wonky, [])
    psi_offenders = get(psi, :offenders, [])
    offenders_set = Set(psi_offenders)

    # 8. Check culprits/faults are not already reported as offenders
    # This must be checked BEFORE key validation
    for culprit in culprits
        key = string(culprit[:key])
        if key in offenders_set
            return (String[], :offender_already_reported)
        end
    end
    for fault in faults
        key = string(fault[:key])
        if key in offenders_set
            return (String[], :offender_already_reported)
        end
    end

    # 9. Build combined validator set for culprit/fault key validation
    # Per graypaper: k = {i_ed | i ∈ λ ∪ κ} \ offenders
    all_validator_keys = Set{String}()
    for v in kappa
        push!(all_validator_keys, string(v[:ed25519]))
    end
    for v in lambda
        push!(all_validator_keys, string(v[:ed25519]))
    end
    valid_keys = setdiff(all_validator_keys, offenders_set)

    # 10. Validate culprit keys exist in valid validator set
    for culprit in culprits
        key = string(culprit[:key])
        if key ∉ valid_keys
            return (String[], :bad_guarantor_key)
        end
    end

    # 11. Validate fault keys exist in valid validator set
    for fault in faults
        key = string(fault[:key])
        if key ∉ valid_keys
            return (String[], :bad_auditor_key)
        end
    end

    # 12. Verify culprit signatures (guarantor signatures over "jam_guarantee" || report_hash)
    for culprit in culprits
        target = string(culprit[:target])
        key_hex = string(culprit[:key])
        sig_hex = string(culprit[:signature])

        pubkey = hex2bytes(startswith(key_hex, "0x") ? key_hex[3:end] : key_hex)
        sig = hex2bytes(startswith(sig_hex, "0x") ? sig_hex[3:end] : sig_hex)
        target_bytes = hex2bytes(startswith(target, "0x") ? target[3:end] : target)

        # Culprit signature is over "jam_guarantee" || report_hash
        message = vcat(Vector{UInt8}("jam_guarantee"), target_bytes)
        if !verify_ed25519(pubkey, message, sig)
            return (String[], :bad_signature)
        end
    end

    # 13. Verify fault signatures (auditor signatures over context || report_hash)
    for fault in faults
        target = string(fault[:target])
        key_hex = string(fault[:key])
        sig_hex = string(fault[:signature])
        vote = fault[:vote]

        pubkey = hex2bytes(startswith(key_hex, "0x") ? key_hex[3:end] : key_hex)
        sig = hex2bytes(startswith(sig_hex, "0x") ? sig_hex[3:end] : sig_hex)
        target_bytes = hex2bytes(startswith(target, "0x") ? target[3:end] : target)

        # Fault signature uses same context as verdict votes
        context = vote ? "jam_valid" : "jam_invalid"
        message = vcat(Vector{UInt8}(context), target_bytes)
        if !verify_ed25519(pubkey, message, sig)
            return (String[], :bad_signature)
        end
    end

    # 14. Check verdicts are not already judged
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

    # 12. Classify verdicts (GOOD, BAD, or WONKY) and validate vote split
    # Per graypaper eq. 89-103: true_votes must be exactly one of:
    # - floor(2V/3) + 1  (GOOD - report is valid)
    # - 0                 (BAD - report is invalid)
    # - floor(V/3)        (WONKY - inconclusive)
    # Where V = total validator count (|kappa|)

    verdict_classifications = Dict{String, Symbol}()  # target -> :good, :bad, or :wonky
    validator_count = length(kappa)

    for verdict in verdicts
        votes = get(verdict, :votes, [])
        true_votes = count(v -> v[:vote] == true, votes)
        target = verdict[:target]

        # Valid vote totals per graypaper
        good_threshold = div(2 * validator_count, 3) + 1  # floor(2V/3) + 1
        wonky_threshold = div(validator_count, 3)          # floor(V/3)
        bad_threshold = 0

        # Check if vote split is valid
        if true_votes == good_threshold
            verdict_classifications[target] = :good
        elseif true_votes == bad_threshold
            verdict_classifications[target] = :bad
        elseif true_votes == wonky_threshold
            verdict_classifications[target] = :wonky
        else
            return (String[], :bad_vote_split)
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
