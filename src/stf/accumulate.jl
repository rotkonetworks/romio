# Accumulate State Transition Function
# Processes work reports and executes accumulate phase

include("../types/basic.jl")
include("../types/accumulate.jl")
include("../test_vectors/loader.jl")
include("../test_vectors/comparison.jl")
include("../pvm/pvm.jl")
using .PVM

# Parse work result from JSON
function parse_work_result(json_result)
    service_id = ServiceId(json_result[:service_id])
    code_hash = parse_hex(json_result[:code_hash])
    payload_hash = parse_hex(json_result[:payload_hash])
    accumulate_gas = Gas(json_result[:accumulate_gas])

    # Parse result (ok or error)
    result = if haskey(json_result[:result], :ok)
        (ok = parse_hex(json_result[:result][:ok]),)
    else
        (error = json_result[:result][:error],)
    end

    return (
        service_id = service_id,
        code_hash = code_hash,
        payload_hash = payload_hash,
        accumulate_gas = accumulate_gas,
        result = result
    )
end

# Parse work report from JSON
function parse_work_report(json_report)
    results = [parse_work_result(r) for r in json_report[:results]]

    return (
        results = results,
        auth_gas_used = Gas(json_report[:auth_gas_used]),
        authorizer_hash = parse_hex(json_report[:authorizer_hash]),
        core_index = UInt16(json_report[:core_index]),
        # TODO: add other fields as needed
    )
end

# Execute accumulate invocation for a work result
function execute_accumulate(
    work_result,
    account::ServiceAccount,
    state::State,
    current_slot::TimeSlot
)::Tuple{ServiceAccount, Bool}
    # Get service code from preimages
    if !haskey(account.preimages, work_result.code_hash)
        # Code not available
        return (account, false)
    end

    service_code = account.preimages[work_result.code_hash]

    # Create implications context
    implications = ImplicationsContext(
        work_result.service_id,
        account,
        state.accounts,
        state.privileges,
        current_slot
    )

    # Create work package context for FETCH host call
    # The service code will fetch the work result via FETCH(selector=7) for work package data
    work_package = Dict{Symbol, Any}(
        :results => [work_result.result.ok]  # Store the work result for FETCH
    )

    # Create host call context with work package
    context = HostCallContext(implications, state.entropy, nothing, work_package, nothing)

    # Prepare input: result from refine phase (for accumulate)
    # If refine succeeded (ok), pass the result; if it failed (error), skip accumulate
    if !haskey(work_result.result, :ok)
        # Refine failed - skip accumulate
        return (account, false)
    end

    # Per graypaper: PVM input for accumulate is encode(timeslot, service_id, len(i))
    # where len(i) is the NUMBER of accumulate inputs (work results), not byte length
    # Encode: timeslot (u32) + service_id (u32) + input_count (u32)
    input = UInt8[]
    # Encode timeslot (little-endian u32)
    append!(input, reinterpret(UInt8, [UInt32(current_slot)]))
    # Encode service_id (little-endian u32)
    append!(input, reinterpret(UInt8, [UInt32(work_result.service_id)]))
    # Encode number of accumulate inputs (u32) - we have 1 work result
    append!(input, reinterpret(UInt8, [UInt32(1)]))

    println("  [INPUT] bytes: $(bytes2hex(input))")
    println("    [0-3] timeslot: $(reinterpret(UInt32, input[1:4])[1])")
    println("    [4-7] service_id: $(reinterpret(UInt32, input[5:8])[1])")
    println("    [8-11] count: $(reinterpret(UInt32, input[9:12])[1])")

    # Execute PVM with accumulate invocation type (entry point 5 per graypaper)
    try
        status, output, gas_used, exports = PVM.execute(
            service_code,
            input,
            UInt64(work_result.accumulate_gas),
            context,
            5  # Entry point 5 for accumulate invocation
        )

        # Check if execution succeeded
        if status != PVM.HALT
            # Execution failed - return unchanged account
            return (account, false)
        end

        # Apply implications from context to service account
        # The host calls (WRITE, etc.) have already modified implications.self
        updated_account = implications.self

        # Update last_acc to current slot (graypaper: accountspostxfer)
        updated_account = ServiceAccount(
            updated_account.code_hash,
            updated_account.balance,
            updated_account.min_acc_gas,
            updated_account.min_memo_gas,
            gratis = updated_account.gratis,
            created = updated_account.created,
            parent = updated_account.parent,
            octets = updated_account.octets,
            items = updated_account.items,
            min_balance = updated_account.min_balance,
            last_acc = UInt32(current_slot),  # Update to current slot
            storage = updated_account.storage,
            preimages = updated_account.preimages,
            preimage_meta = updated_account.preimage_meta
        )

        return (updated_account, true)
    catch e
        # PVM exception error
        println("    ❌ PVM exception: $(typeof(e))")
        if e isa MethodError
            println("      Method: $(e.f)")
            println("      Args: $(typeof(e.args))")
        elseif e isa InexactError
            println("      Function: $(e.func)")
            println("      Args: $(e.args)")
            println("      Stacktrace:")
            for (exc, bt) in Base.catch_stack()
                showerror(stdout, exc, bt[1:min(5, length(bt))])
                println()
            end
        elseif e isa BoundsError
            println("      Array: $(typeof(e.a))")
            println("      Index: $(e.i)")
            println("      Stacktrace:")
            for (exc, bt) in Base.catch_stack()
                showerror(stdout, exc, bt[1:min(10, length(bt))])
                println()
            end
        else
            println("      Error: $e")
            println("      Stacktrace:")
            Base.show_backtrace(stdout, catch_backtrace()[1:min(10, length(catch_backtrace()))])
            println()
        end
        return (account, false)
    end
end

# Accumulate STF
function process_accumulate(
    state::State,
    slot::TimeSlot,
    reports  # WorkReport or parsed JSON (any collection type)
)::Tuple{State, UInt8}

    # Start with current state
    new_accounts = copy(state.accounts)

    # Process each work report
    for json_report in reports
        # Parse work report from JSON
        report = parse_work_report(json_report)

        # Process each work result in the report
        for work_result in report.results
            # Get service account
            if !haskey(new_accounts, work_result.service_id)
                # Service doesn't exist - skip
                continue
            end

            account = new_accounts[work_result.service_id]

            # Verify code hash matches
            if account.code_hash != work_result.code_hash
                # Code hash mismatch - skip
                continue
            end

            # Execute PVM accumulate invocation
            updated_account, success = execute_accumulate(work_result, account, state, slot)
            if success
                # Replace account with updated version
                new_accounts[work_result.service_id] = updated_account
            end
        end
    end

    # Build new state with updated slot and accounts
    new_state = State(
        slot,  # Advance to input slot
        state.entropy,
        new_accounts,
        state.privileges,
        state.accumulated,
        state.ready_queue,
        state.statistics,
        state.validators,
        state.epoch,
        state.validators_next_epoch
    )

    return (new_state, 0x00)  # OK
end

# Run accumulate test vector
function run_accumulate_test_vector(filepath::String)
    println("\n=== Running Accumulate Test Vector: $(basename(filepath)) ===")

    # Load test vector
    tv = load_test_vector(filepath)

    # Parse input
    input_slot = UInt32(tv.input[:slot])
    reports_input = get(tv.input, :reports, [])

    println("Input:")
    println("  Slot: $input_slot")
    println("  Reports: $(length(reports_input))")

    # Run state transition
    (result_state, error_code) = process_accumulate(tv.pre_state, input_slot, reports_input)

    # Check result
    println("\nResult:")
    if error_code == 0x00
        println("  ✓ Success")
    else
        println("  ❌ Error code: 0x$(string(error_code, base=16, pad=2))")
    end

    # Compare states
    states_match = compare_states(tv.post_state, result_state)

    # Final verdict
    println("\n=== Test Vector Result ===")
    if states_match && error_code == 0x00
        println("✅ PASS - Test vector validated successfully!")
        return true
    else
        println("❌ FAIL - Test vector validation failed")
        return false
    end
end

# Export functions
export process_accumulate, run_accumulate_test_vector
