# src/state/transition.jl
# main state transition function

function state_transition(state::State, block::Block)::State
    # validate block
    if !validate_block(state, block)
        error("Invalid block")
    end
    
    # create new state
    new_state = deepcopy(state)
    
    # update timeslot (τ' ≺ H)
    new_state.timeslot = block.header.timeslot
    
    # update recent blocks (β†H ≺ (H, βH))
    update_recent_blocks!(new_state, block.header)
    
    # process in dependency order:
    
    # 1. update entropy (η' ≺ (H, τ, η))
    update_entropy!(new_state, block.header)
    
    # 2. update validators (κ' ≺ (H, τ, κ, γ))
    update_validators!(new_state, block.header)
    
    # 3. process disputes (ψ' ≺ (ED, ψ))
    process_disputes!(new_state, block.extrinsic.disputes)
    
    # 4. clear disputed reports (ρ† ≺ (ED, ρ))
    clear_disputed_reports!(new_state)
    
    # 5. process availability (ρ‡ ≺ (EA, ρ†))
    available_reports = process_availability!(new_state, block.extrinsic.assurances)
    
    # 6. process guarantees (ρ' ≺ (EG, ρ‡, κ, τ'))
    process_guarantees!(new_state, block.extrinsic.guarantees)
    
    # 7. accumulation (ω', ξ', δ‡, χ', ι', ϕ', θ')
    accumulate!(new_state, available_reports)
    
    # 8. process preimages (δ' ≺ (EP, δ‡, τ'))
    process_preimages!(new_state, block.extrinsic.preimages)
    
    # 9. update authorizations (α' ≺ (H, EG, ϕ', α))
    update_authorizations!(new_state, block.extrinsic.guarantees)
    
    # 10. process tickets (γ' ≺ (H, τ, ET, γ, ι, η', κ', ψ'))
    process_tickets!(new_state, block.extrinsic.tickets)
    
    # 11. update statistics (π')
    update_statistics!(new_state, block)
    
    return new_state
end

# helper functions for each transition step
function update_recent_blocks!(state::State, header::Header)
    # get accumulation root from mmb
    accumulation_root = get_accumulation_root(state)
    
    # add new block to recent history
    new_block = RecentBlock(
        hash_header(header),
        H0,  # state root updated later
        accumulation_root,
        Dict{Hash, Hash}()
    )
    
    push!(state.recent_blocks, new_block)
    
    # keep only H most recent
    if length(state.recent_blocks) > H
        popfirst!(state.recent_blocks)
    end
end

function process_availability!(state::State, assurances::AssuranceExtrinsic)::Vector{WorkReport}
    available = WorkReport[]
    
    # count assurances per core
    counts = zeros(Int, C)
    for assurance in assurances.assurances
        for (core, assured) in enumerate(assurance.bitfield)
            if assured && state.pending_reports[core] !== nothing
                counts[core] += 1
            end
        end
    end
    
    # check for 2/3+ majority
    threshold = div(2 * V, 3) + 1
    for core in 1:C
        if counts[core] >= threshold && state.pending_reports[core] !== nothing
            report, _ = state.pending_reports[core]
            push!(available, report)
            state.pending_reports[core] = nothing
        end
    end
    
    return available
end

function accumulate!(state::State, reports::Vector{WorkReport})
    # process each available report
    for report in reports
        # compute accumulation result hash
        accumulation_hash = compute_accumulation_hash(report)
        
        # add to accumulation history
        if isempty(state.accumulation_history)
            push!(state.accumulation_history, Set{Hash}([accumulation_hash]))
        else
            push!(last(state.accumulation_history), accumulation_hash)
        end
        
        # process each work digest
        for digest in report.digests
            # compute output for this service
            output = compute_digest_output(digest)
            
            # add to merkle mountain belt
            add_accumulation_output!(state, digest.service, output)
            
            # update service state if needed
            if haskey(state.services, digest.service)
                service = state.services[digest.service]
                service.last_accumulation = state.timeslot
                
                # update statistics
                if !haskey(state.statistics.service_stats, digest.service)
                    state.statistics.service_stats[digest.service] = ServiceStats(0, 0)
                end
                stats = state.statistics.service_stats[digest.service]
                state.statistics.service_stats[digest.service] = ServiceStats(
                    stats.accumulations + 1,
                    stats.total_gas + digest.gas_used
                )
            end
        end
    end
    
    # trim accumulation history to size limit
    while length(state.accumulation_history) > 1024
        popfirst!(state.accumulation_history)
    end
end

function compute_accumulation_hash(report::WorkReport)::Hash
    # hash entire work report
    data = Vector{UInt8}()
    append!(data, encode_uint16(report.core_index))
    append!(data, report.authorizer_hash)
    append!(data, encode_uint64(report.gas_used))
    return Hash(keccak256(data))
end

function compute_digest_output(digest::WorkDigest)::Hash
    # hash the digest result
    data = Vector{UInt8}()
    append!(data, encode_uint32(digest.service))
    append!(data, digest.code_hash)
    append!(data, digest.payload_hash)
    append!(data, encode_uint64(digest.gas_used))
    
    # add result bytes
    if digest.result isa Symbol
        append!(data, b"error")
        append!(data, string(digest.result))
    else
        append!(data, digest.result)
    end
    
    return Hash(keccak256(data))
end

# add missing encoding helper
function encode_uint16(n::UInt16)::Vector{UInt8}
    [
        UInt8((n >> 8) & 0xff),
        UInt8(n & 0xff)
    ]
end

# stub implementations for now
function validate_block(state::State, block::Block)
    return true
end

function current_time()
    return floor(Int, time() - JAM_EPOCH)
end

function update_entropy!(state::State, header::Header)
    # todo: implement
end

function update_validators!(state::State, header::Header)
    # todo: implement
end

function process_disputes!(state::State, disputes::DisputeExtrinsic)
    # todo: implement
end

function clear_disputed_reports!(state::State)
    # todo: implement
end

function process_guarantees!(state::State, guarantees::GuaranteeExtrinsic)
    # todo: implement
end

function process_preimages!(state::State, preimages::PreimageExtrinsic)
    # todo: implement
end

function update_authorizations!(state::State, guarantees::GuaranteeExtrinsic)
    # todo: implement
end

function process_tickets!(state::State, tickets::TicketExtrinsic)
    # todo: implement
end

function update_statistics!(state::State, block::Block)
    # todo: implement
end

function verify_seal(header::Header, key::BandersnatchKey)
    # todo: implement signature verification
    return true
end

function hash_header(header::Header)::Hash
    # todo: implement proper header hashing
    return H0
end
