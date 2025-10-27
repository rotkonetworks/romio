# validation functions for state transitions

# validate block header
function validate_header(header::Header, state::State)::Tuple{Bool, String}
    # check timeslot progression
    if header.timeslot <= state.timeslot
        return (false, "Timeslot must be greater than current state timeslot")
    end

    # check timeslot not too far in future (max 10 slots)
    if header.timeslot > state.timeslot + 10
        return (false, "Timeslot too far in future")
    end

    # check parent hash exists in recent blocks
    if !isempty(state.recent_blocks)
        parent_found = false
        for block in state.recent_blocks
            if block.header_hash == header.parent_hash
                parent_found = true
                break
            end
        end
        if !parent_found && header.parent_hash != H0
            return (false, "Parent hash not in recent blocks")
        end
    end

    # validate epoch marker
    if header.epoch_marker !== nothing
        if header.timeslot % E != 0
            return (false, "Epoch marker only allowed at epoch boundary")
        end
    end

    return (true, "")
end

# validate extrinsic data
function validate_extrinsic(extrinsic::Extrinsic, state::State)::Tuple{Bool, String}
    # validate tickets
    for (attempt, proof) in extrinsic.tickets.entries
        if attempt > 100  # reasonable limit
            return (false, "Ticket attempt too high")
        end
    end

    # validate guarantees
    for guarantee in extrinsic.guarantees.guarantees
        # check core index is valid
        if guarantee.report.core_index > C
            return (false, "Invalid core index in guarantee")
        end

        # check credentials count (2 or 3 validators)
        if length(guarantee.credentials) < 2 || length(guarantee.credentials) > 3
            return (false, "Invalid credential count in guarantee")
        end

        # check validators are unique
        validator_set = Set{Int}()
        for cred in guarantee.credentials
            if cred[1] in validator_set
                return (false, "Duplicate validators in guarantee")
            end
            push!(validator_set, cred[1])
        end
    end

    # validate assurances
    for assurance in extrinsic.assurances.assurances
        # check validator index
        if assurance.validator_index > V
            return (false, "Invalid validator index in assurance")
        end

        # check bitfield length
        if length(assurance.bitfield) != C
            return (false, "Invalid bitfield length in assurance")
        end
    end

    # validate verdicts in disputes
    for verdict in extrinsic.disputes.verdicts
        if verdict.epoch > state.timeslot ÷ E
            return (false, "Verdict epoch in future")
        end

        # check judgments are valid
        for (judgment, validator_idx, sig) in verdict.judgments
            if validator_idx > V
                return (false, "Invalid validator in verdict")
            end
        end
    end

    return (true, "")
end

# validate work report
function validate_work_report(report::WorkReport, state::State)::Tuple{Bool, String}
    # check core index
    if report.core_index > C
        return (false, "Invalid core index")
    end

    # check authorizer exists in pool
    if report.authorizer_hash ∉ state.authorizations[report.core_index]
        return (false, "Authorizer not in pool")
    end

    # validate digests
    total_gas = Gas(0)
    for digest in report.digests
        # check service exists
        if !haskey(state.services, digest.service)
            return (false, "Service does not exist")
        end

        # check code hash matches
        service = state.services[digest.service]
        if digest.code_hash != service.code_hash
            return (false, "Code hash mismatch")
        end

        # check gas limits
        if digest.gas_accumulate < service.threshold_gas
            return (false, "Insufficient gas for accumulation")
        end

        total_gas += digest.gas_accumulate
    end

    # check total gas limit
    if total_gas > Gas(1000000)  # max gas per report
        return (false, "Total gas exceeds limit")
    end

    # validate prerequisites
    for prereq in report.context.prerequisites
        if prereq ∉ state.accumulated
            return (false, "Prerequisite not accumulated")
        end
    end

    return (true, "")
end

# validate state transition
function validate_transition(
    old_state::State,
    new_state::State,
    block::Block
)::Tuple{Bool, String}
    # check timeslot updated correctly
    if new_state.timeslot != block.header.timeslot
        return (false, "Timeslot not updated correctly")
    end

    # check validators rotated at epoch boundary
    if block.header.timeslot % E == 0 && block.header.epoch_marker !== nothing
        if new_state.previous_validators != old_state.current_validators
            return (false, "Previous validators not updated correctly")
        end
    end

    # check entropy accumulated
    if new_state.entropy[1] == old_state.entropy[1]
        return (false, "Entropy not accumulated")
    end

    # check recent blocks updated
    if length(new_state.recent_blocks) == 0
        return (false, "Recent blocks not updated")
    end

    return (true, "")
end

# comprehensive block validation
function validate_block(state::State, block::Block)::Tuple{Bool, String}
    # validate header
    valid, msg = validate_header(block.header, state)
    if !valid
        return (false, "Header validation failed: $msg")
    end

    # validate extrinsic
    valid, msg = validate_extrinsic(block.extrinsic, state)
    if !valid
        return (false, "Extrinsic validation failed: $msg")
    end

    # validate each work report
    for guarantee in block.extrinsic.guarantees.guarantees
        valid, msg = validate_work_report(guarantee.report, state)
        if !valid
            return (false, "Work report validation failed: $msg")
        end
    end

    return (true, "")
end

export validate_header, validate_extrinsic, validate_work_report,
       validate_transition, validate_block