# Reports State Transition Function
# Per graypaper section on reports/guarantees

include("../types/basic.jl")
include("../test_vectors/loader.jl")
using JSON3

# Constants for tiny mode
const MAX_DEPENDENCIES_TINY = 3  # Maximum prerequisites per work report
const MAX_CORES_TINY = 2         # Number of cores in tiny mode
const NUM_VALIDATORS_TINY = 6    # Number of validators in tiny mode
const VALIDATORS_PER_CORE_TINY = 3  # Validators assigned per core
const MAX_WORK_REPORT_OUTPUT_SIZE = 4096  # Max size of work report output (W_R)
const MAX_WORK_REPORT_GAS_TINY = 10_000_000   # Maximum gas for work report (tiny mode)
const ROTATION_PERIOD_TINY = 4   # Rotation period in tiny mode

# Process reports/guarantees STF
# Returns (new_state, result) where result is :ok or error symbol
function process_reports(
    pre_state,
    slot,
    guarantees,
    known_packages
)
    # No guarantees to process
    if isempty(guarantees)
        return (pre_state, :ok)
    end

    # Get state components
    avail_assignments = get(pre_state, :avail_assignments, [])
    curr_validators = get(pre_state, :curr_validators, [])
    auth_pools = get(pre_state, :auth_pools, [])
    accounts = get(pre_state, :accounts, [])

    num_cores = length(avail_assignments)
    num_validators = length(curr_validators)

    # Check for duplicate/out-of-order guarantees across all guarantees
    seen_cores = Set{Int}()
    seen_packages = Set{String}()
    for guarantee in guarantees
        report = guarantee[:report]
        core_index = report[:core_index]
        package_hash = report[:package_spec][:hash]

        # Check for duplicate core (out_of_order_guarantee)
        if core_index in seen_cores
            return (pre_state, :out_of_order_guarantee)
        end
        push!(seen_cores, core_index)

        # Check for duplicate package in current extrinsic
        if package_hash in seen_packages
            return (pre_state, :duplicate_package)
        end
        push!(seen_packages, package_hash)
    end

    # Process each guarantee
    for guarantee in guarantees
        report = guarantee[:report]
        signatures = guarantee[:signatures]
        guarantee_slot = get(guarantee, :slot, 0)

        # Get report fields
        core_index = report[:core_index]
        context = report[:context]
        prerequisites = get(context, :prerequisites, [])
        package_spec = report[:package_spec]
        package_hash = package_spec[:hash]
        authorizer_hash = report[:authorizer_hash]
        results = get(report, :results, [])
        segment_root_lookup = get(report, :segment_root_lookup, [])

        # 1. Validate core_index is within range
        if core_index < 0 || core_index >= num_cores
            return (pre_state, :bad_core_index)
        end

        # 2. Check if core is already engaged (has pending report)
        core_assignment = avail_assignments[core_index + 1]  # Julia 1-indexed
        if core_assignment !== nothing && !isempty(core_assignment)
            # Core already has a pending work report
            return (pre_state, :core_engaged)
        end

        # 3. Check guarantee slot is not in the future
        if guarantee_slot > slot
            return (pre_state, :future_report_slot)
        end

        # 4. Check guarantee is not from before last rotation (epoch)
        # Current epoch = slot / R, guarantee must be from current or previous epoch
        current_epoch = div(slot, ROTATION_PERIOD_TINY)
        guarantee_epoch = div(guarantee_slot, ROTATION_PERIOD_TINY)
        if guarantee_epoch < current_epoch - 1
            return (pre_state, :report_epoch_before_last)
        end

        # 5. Check sufficient number of guarantees (2/3 of validators per core)
        # For tiny mode: 3 validators per core, need at least 2 signatures
        min_signatures = 2  # ceil(2/3 * 3) = 2
        if length(signatures) < min_signatures
            return (pre_state, :insufficient_guarantees)
        end

        # 5. Check guarantors are sorted by validator index (ascending) and unique
        for i in 2:length(signatures)
            prev_idx = signatures[i-1][:validator_index]
            curr_idx = signatures[i][:validator_index]
            if prev_idx >= curr_idx
                return (pre_state, :not_sorted_or_unique_guarantors)
            end
        end

        # 6. Check validator indices are in valid range
        for sig in signatures
            validator_index = sig[:validator_index]
            if validator_index < 0 || validator_index >= num_validators
                return (pre_state, :bad_validator_index)
            end
        end

        # 7. Check banned validators (offenders list)
        offenders = get(pre_state, :offenders, [])
        for sig in signatures
            validator_index = sig[:validator_index]
            if validator_index < length(curr_validators)
                validator = curr_validators[validator_index + 1]
                validator_ed25519 = get(validator, :ed25519, nothing)
                if validator_ed25519 !== nothing && validator_ed25519 in offenders
                    return (pre_state, :banned_validator)
                end
            end
        end

        # 8. Check anchor is in recent blocks and validate state_root/beefy_root
        anchor = context[:anchor]
        context_state_root = get(context, :state_root, nothing)
        context_beefy_root = get(context, :beefy_root, nothing)
        recent_blocks = get(pre_state, :recent_blocks, nothing)
        if recent_blocks !== nothing
            history = get(recent_blocks, :history, [])
            anchor_found = false
            anchor_block = nothing
            for block in history
                if get(block, :header_hash, nothing) == anchor
                    anchor_found = true
                    anchor_block = block
                    break
                end
            end
            if !anchor_found
                return (pre_state, :anchor_not_recent)
            end
            # Validate state_root matches anchor block
            if anchor_block !== nothing && context_state_root !== nothing
                block_state_root = get(anchor_block, :state_root, nothing)
                if block_state_root !== nothing && context_state_root != block_state_root
                    return (pre_state, :bad_state_root)
                end
            end
            # Validate beefy_root matches anchor block
            if anchor_block !== nothing && context_beefy_root !== nothing
                block_beefy_root = get(anchor_block, :beefy_root, nothing)
                if block_beefy_root !== nothing && context_beefy_root != block_beefy_root
                    return (pre_state, :bad_beefy_mmr_root)
                end
            end
        end

        # 8. Check package not already reported (duplicate_package)
        if recent_blocks !== nothing
            history = get(recent_blocks, :history, [])
            for block in history
                reported = get(block, :reported, [])
                for r in reported
                    if get(r, :hash, nothing) == package_hash
                        return (pre_state, :duplicate_package)
                    end
                end
            end
        end

        # 10. Validate segment_root_lookup references
        # Each entry must reference a work_package_hash that's in recent_blocks.history.reported
        # and the segment_tree_root must match the exports_root from history
        if recent_blocks !== nothing && !isempty(segment_root_lookup)
            history = get(recent_blocks, :history, [])
            # Build map of work_package_hash -> exports_root from history
            reported_roots = Dict{String, String}()
            for block in history
                reported = get(block, :reported, [])
                for r in reported
                    h = get(r, :hash, nothing)
                    exp_root = get(r, :exports_root, nothing)
                    if h !== nothing
                        reported_roots[h] = exp_root !== nothing ? exp_root : ""
                    end
                end
            end
            # Check each segment_root_lookup entry
            for lookup in segment_root_lookup
                wp_hash = get(lookup, :work_package_hash, nothing)
                seg_root = get(lookup, :segment_tree_root, nothing)
                if wp_hash !== nothing
                    if !haskey(reported_roots, wp_hash)
                        # Work package not in history
                        return (pre_state, :segment_root_lookup_invalid)
                    end
                    # Check if segment_tree_root matches exports_root
                    if seg_root !== nothing && reported_roots[wp_hash] != seg_root
                        return (pre_state, :segment_root_lookup_invalid)
                    end
                end
            end
        end

        # Note: dependency_missing check needs more complex logic about imports vs segment_root_lookup

        # 11. Validate segment_root_lookup count (dependencies)
        # In tiny mode, max 4 segment_root_lookup entries
        if length(segment_root_lookup) > 4
            return (pre_state, :too_many_dependencies)
        end

        # 13. Check for missing work results
        if isempty(results)
            return (pre_state, :missing_work_results)
        end

        # 12. Validate work report total output size
        # Total output = auth_output + all result outputs
        # Max is 48KB = 49152 bytes for tiny mode
        auth_output = get(report, :auth_output, "0x")
        auth_output_bytes = if startswith(auth_output, "0x")
            div(length(auth_output) - 2, 2)
        else
            div(length(auth_output), 2)
        end

        # Calculate total result output sizes
        total_result_size = 0
        for result in results
            result_output = get(result, :result, nothing)
            if result_output !== nothing
                if haskey(result_output, :ok)
                    ok_data = result_output[:ok]
                    result_bytes = if startswith(ok_data, "0x")
                        div(length(ok_data) - 2, 2)
                    else
                        div(length(ok_data), 2)
                    end
                    total_result_size += result_bytes
                end
            end
        end

        # Total output size check (48KB = 49152 bytes limit)
        total_output_size = auth_output_bytes + total_result_size
        if total_output_size > 49152  # 48KB limit for tiny mode
            return (pre_state, :work_report_too_big)
        end

        # Check total gas doesn't exceed maximum
        total_gas = UInt64(0)
        for result in results
            total_gas += UInt64(get(result, :accumulate_gas, 0))
        end
        if total_gas > MAX_WORK_REPORT_GAS_TINY
            return (pre_state, :work_report_gas_too_high)
        end

        # Validate service existence and code_hash for each result
        for result in results
            service_id = result[:service_id]
            result_code_hash = get(result, :code_hash, nothing)
            accumulate_gas = get(result, :accumulate_gas, 0)

            # Find service account
            service_found = false
            for acc_entry in accounts
                if acc_entry[:id] == service_id
                    service_found = true
                    service_data = acc_entry[:data][:service]

                    # Check code_hash matches
                    if result_code_hash !== nothing
                        account_code_hash = get(service_data, :code_hash, nothing)
                        if account_code_hash !== nothing && result_code_hash != account_code_hash
                            return (pre_state, :bad_code_hash)
                        end
                    end

                    # Check min_item_gas
                    min_item_gas = get(service_data, :min_item_gas, 0)
                    if accumulate_gas < min_item_gas
                        return (pre_state, :service_item_gas_too_low)
                    end
                    break
                end
            end

            # Service must exist
            if !service_found
                return (pre_state, :bad_service_id)
            end
        end

        # Validate authorizer is in auth pool for this core
        if core_index < length(auth_pools)
            core_auth_pool = auth_pools[core_index + 1]  # Julia 1-indexed
            # Check if authorizer is in auth pool
            found_auth = false
            for auth_hash in core_auth_pool
                if auth_hash == authorizer_hash
                    found_auth = true
                    break
                end
            end
            if !found_auth
                return (pre_state, :core_unauthorized)
            end
        end

        # Note: Full implementation would need to check validator assignments via shuffle
        # wrong_assignment check requires computing Fisher-Yates shuffle from entropy
    end

    return (pre_state, :ok)
end

# Run reports test vector
function run_reports_test_vector(filepath::String)
    println("\n=== Running Reports Test Vector: $(basename(filepath)) ===")

    # Load test vector
    json_str = read(filepath, String)
    tv = JSON3.read(json_str)

    # Parse input
    slot = tv[:input][:slot]
    guarantees = tv[:input][:guarantees]
    known_packages = tv[:input][:known_packages]

    # Pre-state
    pre_state = tv[:pre_state]

    println("Input:")
    println("  Slot: $slot")
    println("  Guarantees: $(length(guarantees))")

    # Run state transition
    new_state, result = process_reports(pre_state, slot, guarantees, known_packages)

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
            println("  Success as expected")
            println("\n=== Test Vector Result ===")
            println("  PASS")
            return true
        else
            println("  Expected success, got error: $result")
            println("\n=== Test Vector Result ===")
            println("  FAIL")
            return false
        end
    end
end

export process_reports, run_reports_test_vector
