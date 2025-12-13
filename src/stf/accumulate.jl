# Accumulate State Transition Function
# Processes work reports and executes accumulate phase

include("../types/basic.jl")
include("../types/accumulate.jl")
include("../test_vectors/loader.jl")
include("../test_vectors/comparison.jl")
include("../pvm/pvm.jl")
include("../encoding/jam.jl")
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

    # Parse context which contains prerequisites
    context = json_report[:context]
    prerequisites = if haskey(context, :prerequisites)
        [parse_hex(p) for p in context[:prerequisites]]
    else
        Vector{Vector{UInt8}}()
    end

    # Parse package_spec for operandtuple fields
    package_spec = json_report[:package_spec]
    package_hash = parse_hex(package_spec[:hash])
    erasure_root = parse_hex(package_spec[:erasure_root])  # Used as seg_root
    exports_root = parse_hex(package_spec[:exports_root])  # Used in operand encoding

    # Parse authorization output if available
    auth_output = haskey(json_report, :auth_output) ? parse_hex(json_report[:auth_output]) : UInt8[]

    return (
        results = results,
        auth_gas_used = Gas(json_report[:auth_gas_used]),
        authorizer_hash = parse_hex(json_report[:authorizer_hash]),
        core_index = UInt16(json_report[:core_index]),
        prerequisites = prerequisites,
        package_hash = package_hash,
        seg_root = erasure_root,
        exports_root = exports_root,
        auth_output = auth_output,
    )
end

# Execute accumulate invocation for a work result
function execute_accumulate(
    work_result,
    work_report,  # Full work report for operandtuple fields
    account::ServiceAccount,
    state::State,
    current_slot::TimeSlot
)::Tuple{ServiceAccount, Dict{ServiceId, ServiceAccount}, Bool}
    # Get service code from preimages
    if !haskey(account.preimages, work_result.code_hash)
        # Code not available - still update last_acc per graypaper
        println("  [ACCUMULATE] Code not available for hash $(bytes2hex(work_result.code_hash))")
        # Create updated account with last_acc set to current slot
        updated_account = ServiceAccount(
            account.code_hash,
            account.storage,
            account.preimages,
            account.requests,
            account.balance,
            account.min_balance,
            account.min_acc_gas,
            account.min_memo_gas,
            account.octets,
            account.items,
            account.gratis,
            account.created,
            UInt32(current_slot),  # Update last_acc to current slot
            account.parent
        )
        return (updated_account, state.accounts, true)  # true = success (account was updated)
    end

    service_code = account.preimages[work_result.code_hash]
    println("  [ACCUMULATE] Executing service $(work_result.service_id) with code hash $(bytes2hex(work_result.code_hash))")

    # Create implications context
    implications = ImplicationsContext(
        work_result.service_id,
        account,
        state.accounts,
        state.privileges,
        current_slot
    )
    println("  [ACCUMULATE] Initial exceptional_state: $(implications.exceptional_state !== nothing)")

    # Build operandtuple (Operand) for FETCH access
    # Per graypaper Operand codec:
    #   hash (32 bytes) - WorkPackageHash
    #   exportsRoot (32 bytes) - ExportsRootHash
    #   authorizerHash (32 bytes)
    #   payloadHash (32 bytes)
    #   gas (varU64) - ServiceGas
    #   result (WorkExecResult.Codec) - kind (varU32) + blob if ok
    #   authorizationOutput (blob)
    operandtuple_encoded = UInt8[]

    # hash (32 bytes) - WorkPackageHash from work_report.package_spec
    append!(operandtuple_encoded, work_report.package_hash)

    # exportsRoot (32 bytes) - from work_report.package_spec.exports_root
    append!(operandtuple_encoded, work_report.exports_root)

    # authorizerHash (32 bytes) - from work_report
    append!(operandtuple_encoded, work_report.authorizer_hash)

    # payloadHash (32 bytes) - from work_result
    append!(operandtuple_encoded, work_result.payload_hash)

    # gas (varU64) - JAM compact encoded
    append!(operandtuple_encoded, encode_jam_compact(work_result.accumulate_gas))

    # result (WorkExecResult.Codec) - kind (varU32) + blob if ok
    # kind=0 means "ok", followed by the blob
    append!(operandtuple_encoded, encode_jam_compact(0))  # kind = ok
    append!(operandtuple_encoded, encode_jam_blob(work_result.result.ok))

    # authorizationOutput (blob) - from work_report.auth_output
    append!(operandtuple_encoded, encode_jam_blob(work_report.auth_output))

    println("  [ACCUMULATE] Operandtuple ($(length(operandtuple_encoded)) bytes): $(bytes2hex(operandtuple_encoded))")
    println("    package_hash: $(bytes2hex(work_report.package_hash))")
    println("    seg_root: $(bytes2hex(work_report.seg_root))")
    println("    authorizer: $(bytes2hex(work_report.authorizer_hash))")
    println("    payload_hash: $(bytes2hex(work_result.payload_hash))")
    println("    gas_limit: $(work_result.accumulate_gas)")
    println("    auth_trace: (empty)")
    println("    result: $(bytes2hex(work_result.result.ok))")

    # Create work package context for FETCH host call
    work_package = Dict{Symbol, Any}(
        :results => [operandtuple_encoded]  # Store encoded operandtuple for FETCH
    )

    # Create host call context with work package
    context = HostCallContext(implications, state.entropy, nothing, work_package, nothing)

    # Prepare input: result from refine phase (for accumulate)
    # If refine succeeded (ok), pass the result; if it failed (error), skip accumulate
    if !haskey(work_result.result, :ok)
        # Refine failed - skip accumulate
        return (account, state.accounts, false)
    end

    # Per graypaper: accumulate input = encode{slot, serviceId, argsLength}
    # All fields use JAM compact encoding (varU32)
    # Operand tuples are accessed via FETCH host call, not inline
    input_slot = UInt32(current_slot)
    input_service_id = UInt32(work_result.service_id)
    input_count = 1  # Number of operand tuples (work results)

    # Build input buffer: just the header
    input = UInt8[]
    append!(input, encode_jam_compact(input_slot))
    append!(input, encode_jam_compact(input_service_id))
    append!(input, encode_jam_compact(input_count))

    println("  [ACCUMULATE] Input: slot=$input_slot, service_id=$input_service_id, count=$input_count ($(length(input)) bytes)")
    println("  [ACCUMULATE] Account balance=$(account.balance), min_acc_gas=$(account.min_acc_gas), items=$(account.items)")

    # Execute PVM with accumulate invocation type
    # Per graypaper \Psi_M invocation: accumulate uses entry point 5
    # Entry points: 0=is_authorized, 5=accumulate (Ψ_A), 10=refine (Ψ_R), 15=on_transfer (Ψ_T)
    try
        status, output, gas_used, exports = PVM.execute(
            service_code,
            input,
            UInt64(work_result.accumulate_gas),
            context,
            5,  # Entry point 5 - accumulate (Ψ_A) per graypaper
            nothing,  # r0 = default (0xFFFF0000)
            nothing   # r6 = 0 (count is in input buffer, not r6)
        )

        # println("  [EXECUTE] status=$status, PVM.PANIC=$(PVM.PANIC), PVM.HALT=$(PVM.HALT)")
        # println("  [EXECUTE] status==PVM.PANIC: $(status == PVM.PANIC)")
        # println("  [EXECUTE] implications.self.storage items: $(length(implications.self.storage))")
        # if implications.exceptional_state !== nothing
        #     println("  [EXECUTE] implications.exceptional_state.self.storage items: $(length(implications.exceptional_state.self.storage))")
        # end

        # Per graypaper: on exceptional exit, use appropriate state
        # PANIC/OOG: use imY (exceptional_state) - checkpoint state
        # FAULT: use imX (current state) - work done before fault
        # HALT: use imX (current state)
        # Per graypaper: last_acc is ALWAYS updated when accumulate runs,
        # regardless of exit status (tracked in statistics for any service with count>0 or gas>0)

        # Helper to create account with updated last_acc
        function update_last_acc(acct::ServiceAccount, slot::UInt32)
            ServiceAccount(
                acct.code_hash,
                acct.storage,
                acct.preimages,
                acct.requests,
                acct.balance,
                acct.min_balance,
                acct.min_acc_gas,
                acct.min_memo_gas,
                acct.octets,
                acct.items,
                acct.gratis,
                acct.created,
                slot,  # Update last_acc to current slot
                acct.parent
            )
        end

        if status == PVM.PANIC || status == PVM.OOG
            # Exceptional exit (panic/oog) - use imY (exceptional_state) per graypaper
            if implications.exceptional_state !== nothing
                # Use the exceptional state (imY) - state at last checkpoint
                # But still update last_acc since accumulate was invoked
                updated_account = update_last_acc(implications.exceptional_state.self, UInt32(current_slot))
                return (updated_account, implications.exceptional_state.accounts, true)
            else
                # No exceptional state means service failed before checkpoint
                # Still update last_acc since accumulate was invoked
                updated_account = update_last_acc(account, UInt32(current_slot))
                return (updated_account, state.accounts, true)
            end
        elseif status == PVM.FAULT
            # Memory fault - use imX (current state) with work done before fault
            # Still update last_acc since accumulate was invoked
            updated_account = update_last_acc(implications.self, UInt32(current_slot))
            return (updated_account, implications.accounts, true)
        elseif status == PVM.HALT
            # Normal exit - use imX state with last_acc updated
            updated_account = update_last_acc(implications.self, UInt32(current_slot))
            return (updated_account, implications.accounts, true)
        else
            # Unknown status - return unchanged account
            return (account, state.accounts, false)
        end
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
        return (account, state.accounts, false)
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

    # Process ready_queue items with no dependencies
    # Ready queue contains work reports that were previously queued due to unmet prerequisites
    for queued_item in state.ready_queue
        if queued_item === nothing
            # Empty slot in ring buffer
            continue
        end

        # Check if this item has dependencies
        dependencies = if haskey(queued_item, :dependencies) && queued_item[:dependencies] !== nothing
            queued_item[:dependencies]
        else
            []
        end

        # Skip if item still has unmet dependencies
        # TODO: implement proper dependency resolution
        if length(dependencies) > 0
            continue
        end

        # Process the queued report
        queued_report = queued_item[:report]

        # Parse the queued report to get work_report structure
        parsed_report = parse_work_report(queued_report)

        # Process each work result in the queued report
        for work_result in parsed_report.results
            # Get service account
            if !haskey(new_accounts, work_result.service_id)
                continue
            end

            account = new_accounts[work_result.service_id]

            # Verify code hash matches
            if account.code_hash != work_result.code_hash
                continue
            end

            # Execute PVM accumulate invocation
            # println("  [ACCUMULATE] Processing queued work for service $(work_result.service_id)")
            updated_account, updated_accounts, success = execute_accumulate(work_result, parsed_report, account, state, slot)
            if success
                # Merge updated accounts (includes deletions from EJECT)
                new_accounts = updated_accounts
                new_accounts[work_result.service_id] = updated_account
            end
        end
    end

    # Process each incoming work report
    println("  [DEBUG] Processing $(length(reports)) incoming reports")
    for (ri, json_report) in enumerate(reports)
        # Parse work report from JSON
        report = parse_work_report(json_report)
        println("  [DEBUG] Report $ri: $(length(report.results)) results, $(length(report.prerequisites)) prerequisites")

        # Check if report has unmet prerequisites
        # TODO: implement proper prerequisite checking against state
        # For now, if prerequisites exist, skip processing (queue to ready_queue)
        if length(report.prerequisites) > 0
            # println("  [ACCUMULATE] Skipping report with $(length(report.prerequisites)) prerequisites (should be queued)")
            continue
        end

        # Process each work result in the report
        for work_result in report.results
            # Get service account
            if !haskey(new_accounts, work_result.service_id)
                # Service doesn't exist - skip
                println("  [SKIP] Service $(work_result.service_id) not in accounts")
                continue
            end

            account = new_accounts[work_result.service_id]

            # Verify code hash matches
            if account.code_hash != work_result.code_hash
                # Code hash mismatch - skip
                println("  [SKIP] Code hash mismatch for service $(work_result.service_id)")
                println("    Account: $(bytes2hex(account.code_hash))")
                println("    Work:    $(bytes2hex(work_result.code_hash))")
                continue
            end

            # Execute PVM accumulate invocation
            updated_account, updated_accounts, success = execute_accumulate(work_result, report, account, state, slot)
            if success
                # Merge updated accounts (includes deletions from EJECT)
                new_accounts = updated_accounts
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
