# Best chain selection mechanism

include("grandpa.jl")
include("safrole.jl")
include("../state/state.jl")
include("../blocks/block.jl")

# Chain information
struct ChainInfo
    hash::Hash
    number::UInt64
    parent_hash::Hash
    state_root::Hash
    is_audited::Bool
    safrole_primary::Bool  # block was produced by designated primary
    total_difficulty::UInt64  # for tie-breaking
end

# Fork choice rule
@enum ForkChoice begin
    LONGEST_CHAIN = 1
    SAFROLE_PRIMARY = 2
    FINALIZED_FIRST = 3
end

# Best chain tracker
mutable struct BestChainTracker
    blocks::Dict{Hash, ChainInfo}
    children::Dict{Hash, Vector{Hash}}
    genesis_hash::Hash
    finalized_hash::Hash
    finalized_number::UInt64
    best_hash::Hash
    best_number::UInt64
    fork_choice::ForkChoice
    disputed_blocks::Set{Hash}  # blocks containing disputed reports
end

# Initialize best chain tracker
function initialize_best_chain(genesis_hash::Hash)::BestChainTracker
    genesis_info = ChainInfo(
        genesis_hash,
        0,
        H0,  # no parent
        H0,  # genesis state root
        true,  # audited
        true,   # primary
        0       # difficulty
    )

    tracker = BestChainTracker(
        Dict(genesis_hash => genesis_info),
        Dict{Hash, Vector{Hash}}(),
        genesis_hash,
        genesis_hash,
        0,
        genesis_hash,
        0,
        LONGEST_CHAIN,
        Set{Hash}()
    )

    return tracker
end

# Add block to chain tracker
function add_block!(
    tracker::BestChainTracker,
    block::Block,
    state::State,
    is_audited::Bool = true
)::Bool
    hash = H(encode(block.header))
    parent_hash = block.header.parent_hash

    # Check if parent exists
    if !haskey(tracker.blocks, parent_hash)
        return false
    end

    parent_info = tracker.blocks[parent_hash]

    # Create chain info
    info = ChainInfo(
        hash,
        parent_info.number + 1,
        parent_hash,
        state.accumulation_log.root,
        is_audited,
        is_safrole_primary(block, state.safrole),
        parent_info.total_difficulty + calculate_difficulty(block, state)
    )

    # Add to tracker
    tracker.blocks[hash] = info

    # Add to children
    if !haskey(tracker.children, parent_hash)
        tracker.children[parent_hash] = Vector{Hash}()
    end
    push!(tracker.children[parent_hash], hash)

    # Update best block
    update_best_block!(tracker)

    return true
end

# Check if block was produced by Safrole primary
function is_safrole_primary(block::Block, safrole::SafroleState)::Bool
    # Check if the block author was the designated author for this timeslot
    seal_key = get_seal_key(safrole, block.header.timeslot)

    if seal_key === nothing
        return false
    end

    if isa(seal_key, BandersnatchKey)
        # Fallback mode - verify seal key matches
        # In real implementation, would extract from seal signature
        return true  # simplified
    else
        # Ticket mode - verify ring VRF
        return verify_seal(block.header, safrole, H0)  # simplified
    end
end

# Calculate block difficulty (for tie-breaking)
function calculate_difficulty(block::Block, state::State)::UInt64
    # Difficulty based on various factors
    difficulty = UInt64(1)

    # Bonus for having more work reports
    difficulty += UInt64(length(block.extrinsic.guarantees.guarantees))

    # Bonus for having assurances
    difficulty += UInt64(length(block.extrinsic.assurances.assurances))

    # Bonus for being on time (within expected slot)
    if block.header.timeslot == state.timeslot + 1
        difficulty += UInt64(10)
    end

    return difficulty
end

# Update best block based on fork choice rule
function update_best_block!(tracker::BestChainTracker)
    old_best = tracker.best_hash

    if tracker.fork_choice == LONGEST_CHAIN
        update_best_longest_chain!(tracker)
    elseif tracker.fork_choice == SAFROLE_PRIMARY
        update_best_safrole_primary!(tracker)
    elseif tracker.fork_choice == FINALIZED_FIRST
        update_best_finalized_first!(tracker)
    end

    # Log if best block changed
    if tracker.best_hash != old_best
        info = tracker.blocks[tracker.best_hash]
        println("Best block updated: $(tracker.best_hash) (number: $(info.number))")
    end
end

# Longest chain rule
function update_best_longest_chain!(tracker::BestChainTracker)
    best_length = tracker.best_number
    best_difficulty = tracker.blocks[tracker.best_hash].total_difficulty

    for (hash, info) in tracker.blocks
        # Skip disputed blocks
        if hash in tracker.disputed_blocks
            continue
        end

        # Must be audited
        if !info.is_audited
            continue
        end

        # Prefer longer chains
        if info.number > best_length ||
           (info.number == best_length && info.total_difficulty > best_difficulty)
            tracker.best_hash = hash
            tracker.best_number = info.number
            best_length = info.number
            best_difficulty = info.total_difficulty
        end
    end
end

# Safrole primary rule (prefer blocks from designated authors)
function update_best_safrole_primary!(tracker::BestChainTracker)
    best_length = tracker.best_number
    best_from_primary = tracker.blocks[tracker.best_hash].safrole_primary

    for (hash, info) in tracker.blocks
        # Skip disputed blocks
        if hash in tracker.disputed_blocks
            continue
        end

        # Must be audited
        if !info.is_audited
            continue
        end

        # Prefer primary blocks, then length
        better = false
        if info.safrole_primary && !best_from_primary
            better = true
        elseif info.safrole_primary == best_from_primary
            if info.number > best_length
                better = true
            elseif info.number == best_length &&
                   info.total_difficulty > tracker.blocks[tracker.best_hash].total_difficulty
                better = true
            end
        end

        if better
            tracker.best_hash = hash
            tracker.best_number = info.number
            best_length = info.number
            best_from_primary = info.safrole_primary
        end
    end
end

# Finalized-first rule (prefer finalized ancestors)
function update_best_finalized_first!(tracker::BestChainTracker)
    best_length = tracker.best_number

    for (hash, info) in tracker.blocks
        # Skip disputed blocks
        if hash in tracker.disputed_blocks
            continue
        end

        # Must be audited
        if !info.is_audited
            continue
        end

        # Must descend from finalized block
        if !descends_from_finalized(tracker, hash)
            continue
        end

        # Prefer longer chains among valid candidates
        if info.number > best_length ||
           (info.number == best_length &&
            info.total_difficulty > tracker.blocks[tracker.best_hash].total_difficulty)
            tracker.best_hash = hash
            tracker.best_number = info.number
            best_length = info.number
        end
    end
end

# Check if block descends from finalized block
function descends_from_finalized(tracker::BestChainTracker, hash::Hash)::Bool
    current = hash

    while current != H0
        if current == tracker.finalized_hash
            return true
        end

        if !haskey(tracker.blocks, current)
            return false
        end

        current = tracker.blocks[current].parent_hash
    end

    return false
end

# Mark block as disputed
function mark_disputed!(tracker::BestChainTracker, hash::Hash)
    push!(tracker.disputed_blocks, hash)

    # Update best block if current best is now disputed
    if hash == tracker.best_hash
        update_best_block!(tracker)
    end

    println("Marked block as disputed: $hash")
end

# Update finalized block
function update_finalized!(tracker::BestChainTracker, hash::Hash, number::UInt64)
    if number > tracker.finalized_number
        tracker.finalized_hash = hash
        tracker.finalized_number = number

        # Clean up old blocks
        cleanup_old_blocks!(tracker)

        println("Finalized block updated: $hash (number: $number)")
    end
end

# Clean up blocks older than finalized
function cleanup_old_blocks!(tracker::BestChainTracker)
    to_remove = Vector{Hash}()

    for (hash, info) in tracker.blocks
        # Keep finalized block and its descendants
        if info.number < tracker.finalized_number &&
           !descends_from_finalized(tracker, hash)
            push!(to_remove, hash)
        end
    end

    # Remove old blocks
    for hash in to_remove
        delete!(tracker.blocks, hash)
        delete!(tracker.children, hash)

        # Remove from parent's children
        for (_, children) in tracker.children
            filter!(h -> h != hash, children)
        end
    end

    if !isempty(to_remove)
        println("Cleaned up $(length(to_remove)) old blocks")
    end
end

# Get chain from genesis to given block
function get_chain(tracker::BestChainTracker, to_hash::Hash)::Vector{Hash}
    chain = Vector{Hash}()
    current = to_hash

    # Build chain backwards
    while current != H0 && haskey(tracker.blocks, current)
        pushfirst!(chain, current)
        current = tracker.blocks[current].parent_hash
    end

    return chain
end

# Get best chain
function get_best_chain(tracker::BestChainTracker)::Vector{Hash}
    return get_chain(tracker, tracker.best_hash)
end

# Check if block is in best chain
function is_in_best_chain(tracker::BestChainTracker, hash::Hash)::Bool
    chain = get_best_chain(tracker)
    return hash in chain
end

# Get block info
function get_block_info(tracker::BestChainTracker, hash::Hash)::Union{Nothing, ChainInfo}
    return get(tracker.blocks, hash, nothing)
end

# Best chain service
mutable struct BestChainService
    tracker::BestChainTracker
    grandpa_service::Union{Nothing, GrandpaService}
    running::Bool
end

function BestChainService(genesis_hash::Hash)
    BestChainService(
        initialize_best_chain(genesis_hash),
        nothing,
        false
    )
end

# Start best chain service
function start_best_chain!(service::BestChainService)
    service.running = true
    println("Best chain service started")
end

# Stop best chain service
function stop_best_chain!(service::BestChainService)
    service.running = false
    println("Best chain service stopped")
end

# Set GRANDPA service
function set_grandpa!(service::BestChainService, grandpa::GrandpaService)
    service.grandpa_service = grandpa
end

# Best chain service tick
function best_chain_tick!(service::BestChainService)
    if !service.running
        return
    end

    # Update finalized block from GRANDPA
    if service.grandpa_service !== nothing
        (fin_hash, fin_number) = get_finalized_block(service.grandpa_service.state)
        update_finalized!(service.tracker, fin_hash, fin_number)
    end

    # Update best block
    update_best_block!(service.tracker)
end

# Get current best block
function get_best_block(service::BestChainService)::Tuple{Hash, UInt64}
    return (service.tracker.best_hash, service.tracker.best_number)
end

# Get finalized block
function get_finalized_block(service::BestChainService)::Tuple{Hash, UInt64}
    return (service.tracker.finalized_hash, service.tracker.finalized_number)
end

export BestChainTracker, BestChainService, ChainInfo, ForkChoice,
       initialize_best_chain, add_block!, mark_disputed!,
       update_finalized!, get_best_chain, is_in_best_chain,
       start_best_chain!, stop_best_chain!, best_chain_tick!,
       get_best_block, get_finalized_block