# complete state transition implementation following graypaper

# Constant for zeroed validator (used in filter_offenders)
const ZEROED_VALIDATOR = ValidatorKey(zeros(UInt8, 32), zeros(UInt8, 32), zeros(UInt8, 144))

function state_transition(state::State, block::Block)::State
    new_state = deepcopy(state)
    H = block.header
    E = block.extrinsic
    
    # τ' ← H (equation 24)
    new_state.timeslot = H.timeslot
    
    # β† ← (H, β) - update recent history with parent state root
    update_recent_history_parent!(new_state, H)
    
    # η' ← (H, τ, η) - entropy accumulation  
    update_entropy!(new_state, H)
    
    # κ' ← (H, τ, κ, γ) - validator rotation
    update_validators!(new_state, H)
    
    # ψ' ← (ED, ψ) - process disputes
    process_disputes!(new_state, E.disputes)
    
    # ρ† ← (ED, ρ) - clear disputed reports
    reports_post_judgement = clear_disputed_reports!(new_state)
    
    # ρ‡ ← (EA, ρ†) - process assurances
    reports_post_guarantees = process_assurances!(new_state, E.assurances, reports_post_judgement)
    
    # ρ' ← (EG, ρ‡, κ, τ') - add guarantees
    process_guarantees!(new_state, E.guarantees, reports_post_guarantees)
    
    # A* - determine available reports
    available_reports = collect_available_reports(new_state, E.assurances, reports_post_judgement)
    
    # accumulation: (ω', ξ', δ‡, χ', ι', φ', θ')
    accumulate_reports!(new_state, available_reports)
    
    # δ' ← (EP, δ‡, τ') - integrate preimages
    process_preimages!(new_state, E.preimages)
    
    # α' ← (H, EG, φ', α) - update authorizations
    update_authorizations!(new_state, E.guarantees)
    
    # γ' ← (H, τ, ET, γ, ι, η', κ', ψ') - process tickets
    process_tickets!(new_state, H, E.tickets)
    
    # π' - update statistics
    update_statistics!(new_state, block)
    
    # β' - final recent history update
    finalize_recent_history!(new_state, H, E.guarantees)
    
    return new_state
end

# entropy update per safrole
function update_entropy!(state::State, header::Header)
    # accumulate vrf output
    hash_input = Vector{UInt8}(undef, 64)
    copyto!(hash_input, 1, state.entropy[1], 1, 32)
    copyto!(hash_input, 33, banderout(header.vrf_signature), 1, 32)
    state.entropy = (
        H(hash_input),
        state.entropy[2],
        state.entropy[3],
        state.entropy[4]
    )
    
    # rotate on epoch boundary
    if header.timeslot % E == 0 && header.epoch_marker !== nothing
        state.entropy = (
            state.entropy[1],
            state.entropy[1],  # η₀ → η₁
            state.entropy[2],  # η₁ → η₂
            state.entropy[3]   # η₂ → η₃
        )
    end
end

# validator rotation per safrole
function update_validators!(state::State, header::Header)
    if header.timeslot % E == 0 && header.epoch_marker !== nothing
        # filter offenders using Φ function
        filtered = filter_offenders(state.queued_validators, state.judgments.offenders)
        
        state.previous_validators = state.current_validators
        state.current_validators = state.safrole.pending
        state.safrole.pending = filtered
        
        # update ring root
        state.safrole.ring_root = compute_ring_root(state.safrole.pending)
    end
end

function filter_offenders(validators::Vector{ValidatorKey}, offenders::Set{Ed25519Key})
    return [v.ed25519 in offenders ? ZEROED_VALIDATOR : v for v in validators]
end

# process assurances and determine available reports
function process_assurances!(state::State, assurances::AssuranceExtrinsic, reports_post_judgement)
    # count assurances per core
    counts = zeros(Int, C)
    for assurance in assurances.assurances
        @inbounds for (core, assured) in enumerate(assurance.bitfield)
            if assured && reports_post_judgement[core] !== nothing
                counts[core] += 1
            end
        end
    end

    # clear timed-out or available reports
    threshold = div(2 * V, 3) + 1
    reports_post_guarantees = copy(reports_post_judgement)

    @inbounds for core in 1:C
        report = reports_post_guarantees[core]
        if report !== nothing
            timed_out = state.timeslot >= report.timestamp + U
            available = counts[core] >= threshold

            if timed_out || available
                reports_post_guarantees[core] = nothing
            end
        end
    end

    return reports_post_guarantees
end

function collect_available_reports(state::State, assurances::AssuranceExtrinsic, reports_post_judgement)
    available = WorkReport[]
    counts = zeros(Int, C)

    for assurance in assurances.assurances
        @inbounds for (core, assured) in enumerate(assurance.bitfield)
            if assured && reports_post_judgement[core] !== nothing
                counts[core] += 1
            end
        end
    end

    threshold = div(2 * V, 3) + 1
    @inbounds for core in 1:C
        if counts[core] >= threshold && reports_post_judgement[core] !== nothing
            push!(available, reports_post_judgement[core].workreport)
        end
    end

    return available
end

# accumulation with dependency resolution
function accumulate_reports!(state::State, available_reports::Vector{WorkReport})
    # partition into immediate and queued
    immediate = WorkReport[]
    queued = Tuple{WorkReport, Set{Hash}}[]
    
    for report in available_reports
        deps = Set(report.context.prerequisites)
        if isempty(deps)
            push!(immediate, report)
        else
            push!(queued, (report, deps))
        end
    end
    
    # process immediate reports
    for report in immediate
        accumulate_single_report!(state, report)
    end
    
    # resolve dependencies and process queued
    accumulated_hashes = Set([hash_work_package(r) for r in immediate])
    
    while !isempty(queued)
        processable = WorkReport[]
        remaining = Tuple{WorkReport, Set{Hash}}[]

        for (report, deps) in queued
            satisfied_deps = deps ∩ accumulated_hashes
            if length(satisfied_deps) == length(deps)
                push!(processable, report)
            else
                push!(remaining, (report, deps - satisfied_deps))
            end
        end
        
        if isempty(processable)
            break  # can't resolve more dependencies
        end
        
        for report in processable
            accumulate_single_report!(state, report)
            push!(accumulated_hashes, hash_work_package(report))
        end
        
        queued = remaining
    end
    
    # update ready queue with unprocessable reports
    append!(state.ready, queued)
end

function accumulate_single_report!(state::State, report::WorkReport)
    # include PVM invocation
    include("../pvm/invocation.jl")

    for digest in report.digests
        if digest.result isa Vector{UInt8}  # successful
            service_id = digest.service

            if haskey(state.services, service_id)
                service = state.services[service_id]

                # invoke PVM accumulation
                result = invoke_accumulate(digest, service, state.accumulation_log.root)

                if result.success
                    output_hash = H(digest.result)

                    # add to accumulation log
                    add_accumulation_output!(state, service_id, output_hash)

                    # update service state
                    service.last_accumulation = state.timeslot

                    # update balance if changed
                    if haskey(result.exports, :balance)
                        service.balance = result.exports[:balance]
                    end
                end
            end
        end
    end
end

# authorization pool update
function update_authorizations!(state::State, guarantees::GuaranteeExtrinsic)
    for core in 1:C
        # remove used authorizers
        used = Set{Hash}()
        for g in guarantees.guarantees
            if g.report.core == core
                push!(used, g.report.authorizer)
            end
        end
        
        # filter pool
        pool = filter(h -> h ∉ used, state.authorizations[core])
        
        # add from queue
        queue_slot = state.timeslot % Q
        if queue_slot < length(state.auth_queue[core])
            push!(pool, state.auth_queue[core][queue_slot + 1])
        end
        
        # keep most recent O entries
        state.authorizations[core] = pool[max(1, end-O+1):end]
    end
end

# safrole ticket processing
function process_tickets!(state::State, header::Header, tickets::TicketExtrinsic)
    epoch = header.timeslot ÷ E
    slot_in_epoch = header.timeslot % E
    
    # only process tickets before tail period
    if slot_in_epoch >= E - Y
        return
    end
    
    # add new tickets to accumulator
    new_tickets = Ticket[]
    for (attempt, proof) in tickets.entries
        # verify ring vrf proof
        if verify_ring_vrf(proof, state.safrole.ring_root, state.entropy[3])
            ticket_id = banderout(proof)
            push!(new_tickets, Ticket(ticket_id, attempt))
        end
    end
    
    # merge and keep best tickets
    all_tickets = Vector{Ticket}(undef, length(state.safrole.ticket_accumulator) + length(new_tickets))
    copyto!(all_tickets, 1, state.safrole.ticket_accumulator, 1, length(state.safrole.ticket_accumulator))
    copyto!(all_tickets, length(state.safrole.ticket_accumulator) + 1, new_tickets, 1, length(new_tickets))
    sort!(all_tickets, by=t->t.identifier)
    state.safrole.ticket_accumulator = all_tickets[1:min(E, length(all_tickets))]
end

# stub for ring vrf verification
function verify_ring_vrf(proof::BandersnatchProof, root::Hash, entropy::Hash)
    # actual implementation would verify bandersnatch ring proof
    return true
end

function banderout(sig::BandersnatchSig)::Hash
    # extract vrf output from signature
    return H(sig.data[1:32])
end

function hash_work_package(report::WorkReport)::Hash
    # compute hash of the work package
    return H(encode(report.specification))
end

function compute_ring_root(validators::Vector{ValidatorKey})::Hash
    # compute merkle root of validator ring
    if isempty(validators)
        return zeros(32)
    end
    # simplified merkle computation - pre-allocate
    data = Vector{UInt8}(undef, 32 * length(validators))
    pos = 1
    @inbounds for v in validators
        copyto!(data, pos, v.bandersnatch, 1, 32)
        pos += 32
    end
    return H(data)
end

# dispute processing
function process_disputes!(state::State, disputes::DisputeExtrinsic)
    # process each verdict
    for verdict in disputes.verdicts
        report_hash = verdict.report_hash

        # process judgments to identify culprits
        for (judgment, validator_index, signature) in verdict.judgments
            if !judgment  # guilty verdict
                if validator_index <= length(state.current_validators)
                    validator_key = state.current_validators[validator_index].ed25519
                    push!(state.judgments.offenders, validator_key)
                    push!(state.judgments.punish_set, validator_index)
                end
            end
        end

        # mark report as bad if majority voted guilty
        guilty_count = count(j -> !j[1], verdict.judgments)
        if guilty_count > length(verdict.judgments) / 2
            push!(state.judgments.bad_reports, report_hash)
        end
    end

    # process culprits
    for culprit in disputes.culprits
        # find validator by key
        for (i, validator) in enumerate(state.current_validators)
            if validator.ed25519 == culprit.key
                push!(state.judgments.offenders, culprit.key)
                push!(state.judgments.punish_set, i)
                break
            end
        end
    end

    # process faults
    for fault in disputes.faults
        # similar processing for fault reports
        for (i, validator) in enumerate(state.current_validators)
            if validator.ed25519 == fault.key
                push!(state.judgments.wonky_reports, fault.target)
                break
            end
        end
    end
end

# clear reports marked as disputed
function clear_disputed_reports!(state::State)
    reports_post_judgement = Vector{Union{Nothing,PendingReport}}(nothing, C)

    for core in 1:C
        if state.pending_reports[core] !== nothing
            report = state.pending_reports[core]
            report_hash = H(encode(report.workreport))

            # keep report unless it's marked as bad
            if report_hash ∉ state.judgments.bad_reports
                reports_post_judgement[core] = report
            end
        end
    end

    state.pending_reports = reports_post_judgement
    return reports_post_judgement
end

# process new guarantees
function process_guarantees!(state::State, guarantees::GuaranteeExtrinsic, reports_post_guarantees)
    for guarantee in guarantees.guarantees
        core = guarantee.report.core_index

        # only process if core is free
        if reports_post_guarantees[core] === nothing
            # verify authorizer is in pool
            if guarantee.report.authorizer_hash in state.authorizations[core]
                # create pending report
                pending = PendingReport(
                    guarantee.report,
                    state.timeslot
                )
                state.pending_reports[core] = pending

                # remove used authorizer from pool
                filter!(h -> h != guarantee.report.authorizer_hash, state.authorizations[core])
            end
        end
    end
end

# integrate preimages into state
function process_preimages!(state::State, preimages::PreimageExtrinsic)
    for (service_id, preimage_data) in preimages.preimages
        # compute hash of preimage data
        preimage_hash = H(preimage_data)

        # check if service exists and store preimage
        if haskey(state.services, service_id)
            service = state.services[service_id]
            # store preimage in service state
            service.preimages[preimage_hash] = preimage_data
        end
    end
end

# update statistics
function update_statistics!(state::State, block::Block)
    # ensure validator stats vectors are initialized
    while length(state.statistics.validator_stats[1]) < length(state.current_validators)
        push!(state.statistics.validator_stats[1], ValidatorStats(0, 0, 0))
    end

    # update validator statistics for block author
    author_index = find_validator_index(state, block.header.author)
    if author_index !== nothing && author_index <= length(state.statistics.validator_stats[1])
        # create new stats with updated values
        old_stats = state.statistics.validator_stats[1][author_index]
        state.statistics.validator_stats[1][author_index] = ValidatorStats(
            old_stats.blocks_produced + 1,
            old_stats.tickets_submitted + length(block.extrinsic.tickets.entries),
            old_stats.disputes_raised
        )
    end

    # update core statistics
    for guarantee in block.extrinsic.guarantees.guarantees
        core = guarantee.report.core_index
        if core <= C
            old_stats = state.statistics.core_stats[core]
            state.statistics.core_stats[core] = CoreStats(
                old_stats.reports_processed + 1,
                old_stats.gas_used + guarantee.report.gas_used
            )
        end
    end

    # update service statistics from accumulation
    for entry in state.last_accumulation
        service_id = entry.service
        if !haskey(state.statistics.service_stats, service_id)
            state.statistics.service_stats[service_id] = ServiceStats(0, 0)
        end
        old_stats = state.statistics.service_stats[service_id]
        state.statistics.service_stats[service_id] = ServiceStats(
            old_stats.accumulations + 1,
            old_stats.total_gas
        )
    end
end

# update recent history with parent state root
function update_recent_history_parent!(state::State, header::Header)
    # add parent state root to recent blocks
    parent_block = RecentBlock(
        header_hash=header.parent_hash,
        state_root=header.parent_state_root,
        accumulation_root=state.accumulation_log.root,
        seal=header.seal
    )

    # keep last H blocks
    push!(state.recent_blocks, parent_block)
    if length(state.recent_blocks) > H
        popfirst!(state.recent_blocks)
    end
end

# finalize recent history
function finalize_recent_history!(state::State, header::Header, guarantees::GuaranteeExtrinsic)
    # collect work package hashes from guarantees
    package_hashes = Set{Hash}()
    for guarantee in guarantees.guarantees
        push!(package_hashes, guarantee.report.specification.package_hash)
    end

    # update recent block with reported packages
    if !isempty(state.recent_blocks)
        state.recent_blocks[end].reported_packages = package_hashes
    end

    # update accumulation log with new entries
    for entry in state.last_accumulation
        add_to_merkle_mountain!(state.accumulation_log, H(encode(entry)))
    end
end

# helper to find validator index
function find_validator_index(state::State, key::Ed25519Key)
    for (i, validator) in enumerate(state.current_validators)
        if validator.ed25519 == key
            return i
        end
    end
    return nothing
end

# helper to add accumulation output
function add_accumulation_output!(state::State, service_id::ServiceId, output_hash::Hash)
    push!(state.last_accumulation, AccumulationEntry(
        service=service_id,
        output=output_hash,
        timeslot=state.timeslot
    ))
end

# helper to add to merkle mountain belt
function add_to_merkle_mountain!(mmb::MerkleMountainBelt, hash::Hash)
    # simplified MMB addition
    push!(mmb.peaks, hash)
    mmb.root = compute_mmb_root(mmb.peaks)
end

function compute_mmb_root(peaks::Vector{Hash})::Hash
    if isempty(peaks)
        return zeros(32)
    elseif length(peaks) == 1
        return peaks[1]
    else
        # Pre-allocate buffer for all peaks
        total_size = 32 * length(peaks)
        hash_input = Vector{UInt8}(undef, total_size)
        pos = 1
        for peak in peaks
            copyto!(hash_input, pos, peak, 1, 32)
            pos += 32
        end
        return H(hash_input)
    end
end
