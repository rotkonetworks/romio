# src/state/transition.jl
# Main state transition function

function state_transition(state::State, block::Block)::State
    # Validate block
    if !validate_block(state, block)
        error("Invalid block")
    end
    
    # Create new state
    new_state = deepcopy(state)
    
    # Update timeslot (τ' ≺ H)
    new_state.timeslot = block.header.timeslot
    
    # Update recent blocks (β†H ≺ (H, βH))
    update_recent_blocks!(new_state, block.header)
    
    # Process in dependency order:
    
    # 1. Update entropy (η' ≺ (H, τ, η))
    update_entropy!(new_state, block.header)
    
    # 2. Update validators (κ' ≺ (H, τ, κ, γ))
    update_validators!(new_state, block.header)
    
    # 3. Process disputes (ψ' ≺ (ED, ψ))
    process_disputes!(new_state, block.extrinsic.disputes)
    
    # 4. Clear disputed reports (ρ† ≺ (ED, ρ))
    clear_disputed_reports!(new_state)
    
    # 5. Process availability (ρ‡ ≺ (EA, ρ†))
    available_reports = process_availability!(new_state, block.extrinsic.assurances)
    
    # 6. Process guarantees (ρ' ≺ (EG, ρ‡, κ, τ'))
    process_guarantees!(new_state, block.extrinsic.guarantees)
    
    # 7. Accumulation (ω', ξ', δ‡, χ', ι', ϕ', θ')
    accumulate!(new_state, available_reports)
    
    # 8. Process preimages (δ' ≺ (EP, δ‡, τ'))
    process_preimages!(new_state, block.extrinsic.preimages)
    
    # 9. Update authorizations (α' ≺ (H, EG, ϕ', α))
    update_authorizations!(new_state, block.extrinsic.guarantees)
    
    # 10. Process tickets (γ' ≺ (H, τ, ET, γ, ι, η', κ', ψ'))
    process_tickets!(new_state, block.extrinsic.tickets)
    
    # 11. Update statistics (π')
    update_statistics!(new_state, block)
    
    return new_state
end

# Helper functions for each transition step
function update_recent_blocks!(state::State, header::Header)
    # Add new block to recent history
    new_block = RecentBlock(
        hash_header(header),
        H0,  # State root updated later
        header.accumulation_root,
        Dict{Hash, Hash}()
    )
    
    push!(state.recent_blocks, new_block)
    
    # Keep only H most recent
    if length(state.recent_blocks) > H
        popfirst!(state.recent_blocks)
    end
end

function process_availability!(state::State, assurances::AssuranceExtrinsic)::Vector{WorkReport}
    available = WorkReport[]
    
    # Count assurances per core
    counts = zeros(Int, C)
    for assurance in assurances.assurances
        for (core, assured) in enumerate(assurance.bitfield)
            if assured && state.pending_reports[core] !== nothing
                counts[core] += 1
            end
        end
    end
    
    # Check for 2/3+ majority
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
