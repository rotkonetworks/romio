# GRANDPA finality mechanism

include("../types/basic.jl")
include("../types/validator.jl")
include("../crypto/hash.jl")
include("../blocks/block.jl")

# GRANDPA vote types
@enum VoteType begin
    PREVOTE = 1
    PRECOMMIT = 2
end

# GRANDPA vote structure
struct GrandpaVote
    round_number::UInt64
    vote_type::VoteType
    block_hash::Hash
    block_number::UInt64
    voter_index::ValidatorId
    signature::Ed25519Sig
end

# GRANDPA round state
mutable struct GrandpaRound
    round_number::UInt64
    prevotes::Dict{ValidatorId, GrandpaVote}
    precommits::Dict{ValidatorId, GrandpaVote}
    prevote_ghost::Union{Nothing, Tuple{Hash, UInt64}}
    precommit_ghost::Union{Nothing, Tuple{Hash, UInt64}}
    completable::Bool
    finalized_block::Union{Nothing, Tuple{Hash, UInt64}}
end

# GRANDPA state
mutable struct GrandpaState
    current_round::UInt64
    rounds::Dict{UInt64, GrandpaRound}
    finalized_block::Tuple{Hash, UInt64}
    validator_set::Vector{ValidatorKey}
    validator_weights::Dict{ValidatorId, UInt64}
    our_validator_id::Union{Nothing, ValidatorId}
end

# Initialize GRANDPA state
function initialize_grandpa(
    validators::Vector{ValidatorKey},
    genesis_hash::Hash,
    our_key::Union{Nothing, ValidatorKey} = nothing
)::GrandpaState
    # Set equal weights for all validators
    weights = Dict{ValidatorId, UInt64}()
    for (i, _) in enumerate(validators)
        weights[i] = 1
    end

    # Find our validator index
    our_id = nothing
    if our_key !== nothing
        for (i, validator) in enumerate(validators)
            if validator.ed25519 == our_key.ed25519
                our_id = i
                break
            end
        end
    end

    GrandpaState(
        1,  # start at round 1
        Dict{UInt64, GrandpaRound}(),
        (genesis_hash, 0),  # genesis block finalized
        validators,
        weights,
        our_id
    )
end

# Create new round
function create_round(round_number::UInt64)::GrandpaRound
    GrandpaRound(
        round_number,
        Dict{ValidatorId, GrandpaVote}(),
        Dict{ValidatorId, GrandpaVote}(),
        nothing,
        nothing,
        false,
        nothing
    )
end

# Get or create round
function get_round!(grandpa::GrandpaState, round_number::UInt64)::GrandpaRound
    if !haskey(grandpa.rounds, round_number)
        grandpa.rounds[round_number] = create_round(round_number)
    end
    return grandpa.rounds[round_number]
end

# Calculate total weight of validator set
function total_weight(grandpa::GrandpaState)::UInt64
    return sum(values(grandpa.validator_weights))
end

# Calculate supermajority threshold (2/3 + 1)
function supermajority_threshold(grandpa::GrandpaState)::UInt64
    total = total_weight(grandpa)
    return (2 * total) ÷ 3 + 1
end

# Get weight of a vote set
function vote_weight(
    votes::Dict{ValidatorId, GrandpaVote},
    weights::Dict{ValidatorId, UInt64}
)::UInt64
    weight = 0
    for voter_id in keys(votes)
        if haskey(weights, voter_id)
            weight += weights[voter_id]
        end
    end
    return weight
end

# Verify vote signature
function verify_vote_signature(vote::GrandpaVote, validator_key::Ed25519Key)::Bool
    # Construct message
    message = vcat(
        reinterpret(UInt8, [vote.round_number]),
        UInt8[vote.vote_type == PREVOTE ? 1 : 2],
        vote.block_hash,
        reinterpret(UInt8, [vote.block_number])
    )

    # In real implementation, would verify Ed25519 signature
    # For now, simplified verification
    return length(vote.signature.data) == 64
end

# Add vote to round
function add_vote!(
    grandpa::GrandpaState,
    vote::GrandpaVote
)::Bool
    # Verify voter is in validator set
    if vote.voter_index > length(grandpa.validator_set)
        return false
    end

    # Verify signature
    validator = grandpa.validator_set[vote.voter_index]
    if !verify_vote_signature(vote, validator.ed25519)
        return false
    end

    # Get round
    round = get_round!(grandpa, vote.round_number)

    # Add vote based on type
    if vote.vote_type == PREVOTE
        round.prevotes[vote.voter_index] = vote
    elseif vote.vote_type == PRECOMMIT
        round.precommits[vote.voter_index] = vote
    else
        return false
    end

    # Update GHOST
    update_ghost!(grandpa, round)

    return true
end

# Calculate GHOST (Greedy Heaviest Observed Sub-Tree)
function calculate_ghost(
    votes::Dict{ValidatorId, GrandpaVote},
    weights::Dict{ValidatorId, UInt64},
    chain_info::Function  # (Hash, UInt64) -> Vector{Tuple{Hash, UInt64}}
)::Union{Nothing, Tuple{Hash, UInt64}}
    if isempty(votes)
        return nothing
    end

    # Group votes by block
    block_weights = Dict{Tuple{Hash, UInt64}, UInt64}()

    for (voter_id, vote) in votes
        block_key = (vote.block_hash, vote.block_number)
        current_weight = get(block_weights, block_key, 0)
        voter_weight = get(weights, voter_id, 0)
        block_weights[block_key] = current_weight + voter_weight
    end

    # Find block with highest weight
    max_weight = 0
    best_block = nothing

    for (block_key, weight) in block_weights
        if weight > max_weight
            max_weight = weight
            best_block = block_key
        end
    end

    return best_block
end

# Update GHOST for round
function update_ghost!(grandpa::GrandpaState, round::GrandpaRound)
    # Simple chain info function (would be more complex in real implementation)
    function chain_info(hash::Hash, number::UInt64)
        return Vector{Tuple{Hash, UInt64}}()
    end

    # Calculate prevote GHOST
    round.prevote_ghost = calculate_ghost(
        round.prevotes,
        grandpa.validator_weights,
        chain_info
    )

    # Calculate precommit GHOST
    round.precommit_ghost = calculate_ghost(
        round.precommits,
        grandpa.validator_weights,
        chain_info
    )

    # Check if round is completable
    update_completability!(grandpa, round)
end

# Update round completability
function update_completability!(grandpa::GrandpaState, round::GrandpaRound)
    threshold = supermajority_threshold(grandpa)

    # Check if we have supermajority prevotes
    prevote_weight = vote_weight(round.prevotes, grandpa.validator_weights)
    has_prevote_supermajority = prevote_weight >= threshold

    # Check if we have supermajority precommits
    precommit_weight = vote_weight(round.precommits, grandpa.validator_weights)
    has_precommit_supermajority = precommit_weight >= threshold

    # Round is completable if we have both supermajorities
    round.completable = has_prevote_supermajority && has_precommit_supermajority

    # If completable and GHOSTs agree, we can finalize
    if round.completable &&
       round.prevote_ghost !== nothing &&
       round.precommit_ghost !== nothing &&
       round.prevote_ghost == round.precommit_ghost

        round.finalized_block = round.precommit_ghost
    end
end

# Create vote
function create_vote(
    grandpa::GrandpaState,
    vote_type::VoteType,
    block_hash::Hash,
    block_number::UInt64,
    validator_key::ValidatorKey
)::Union{Nothing, GrandpaVote}
    if grandpa.our_validator_id === nothing
        return nothing
    end

    # Create message to sign
    message = vcat(
        reinterpret(UInt8, [grandpa.current_round]),
        UInt8[vote_type == PREVOTE ? 1 : 2],
        block_hash,
        reinterpret(UInt8, [block_number])
    )

    # Create signature (simplified)
    signature = Ed25519Sig(vcat(
        H(vcat(validator_key.ed25519, message))[1:32],
        zeros(UInt8, 32)
    ))

    return GrandpaVote(
        grandpa.current_round,
        vote_type,
        block_hash,
        block_number,
        grandpa.our_validator_id,
        signature
    )
end

# Process incoming vote
function process_vote!(grandpa::GrandpaState, vote::GrandpaVote)::Bool
    success = add_vote!(grandpa, vote)

    if success
        # Check if any round became finalized
        check_finalization!(grandpa)
    end

    return success
end

# Check for finalization
function check_finalization!(grandpa::GrandpaState)
    for (round_num, round) in grandpa.rounds
        if round.finalized_block !== nothing
            # Update finalized block if newer
            (hash, number) = round.finalized_block
            if number > grandpa.finalized_block[2]
                grandpa.finalized_block = (hash, number)
                println("GRANDPA: Finalized block $number (round $round_num)")

                # Advance to next round
                if round_num >= grandpa.current_round
                    grandpa.current_round = round_num + 1
                end
            end
        end
    end
end

# Start new round
function start_round!(grandpa::GrandpaState, round_number::UInt64)
    grandpa.current_round = round_number
    get_round!(grandpa, round_number)
    println("GRANDPA: Started round $round_number")
end

# Get current round
function current_round(grandpa::GrandpaState)::GrandpaRound
    return get_round!(grandpa, grandpa.current_round)
end

# Check if block is finalized
function is_finalized(grandpa::GrandpaState, block_hash::Hash, block_number::UInt64)::Bool
    return block_number <= grandpa.finalized_block[2]
end

# Get finalized block info
function get_finalized_block(grandpa::GrandpaState)::Tuple{Hash, UInt64}
    return grandpa.finalized_block
end

# GRANDPA voting service
mutable struct GrandpaService
    state::GrandpaState
    validator_key::Union{Nothing, ValidatorKey}
    round_timeout::Float64
    last_round_start::Float64
    pending_votes::Vector{GrandpaVote}
    running::Bool
end

function GrandpaService(
    validators::Vector{ValidatorKey},
    genesis_hash::Hash,
    validator_key::Union{Nothing, ValidatorKey} = nothing
)
    state = initialize_grandpa(validators, genesis_hash, validator_key)

    GrandpaService(
        state,
        validator_key,
        30.0,  # 30 second round timeout
        time(),
        Vector{GrandpaVote}(),
        false
    )
end

# Start GRANDPA service
function start_grandpa!(service::GrandpaService)
    service.running = true
    service.last_round_start = time()
    start_round!(service.state, 1)
    println("GRANDPA service started")
end

# Stop GRANDPA service
function stop_grandpa!(service::GrandpaService)
    service.running = false
    println("GRANDPA service stopped")
end

# GRANDPA service tick
function grandpa_tick!(
    service::GrandpaService,
    best_block_hash::Hash,
    best_block_number::UInt64
)
    if !service.running
        return
    end

    current_time = time()
    round = current_round(service.state)

    # Process any pending votes
    for vote in service.pending_votes
        process_vote!(service.state, vote)
    end
    empty!(service.pending_votes)

    # Check if we should vote
    if service.validator_key !== nothing && service.state.our_validator_id !== nothing
        voter_id = service.state.our_validator_id

        # Cast prevote if we haven't yet
        if !haskey(round.prevotes, voter_id)
            prevote = create_vote(
                service.state,
                PREVOTE,
                best_block_hash,
                best_block_number,
                service.validator_key
            )

            if prevote !== nothing
                add_vote!(service.state, prevote)
                println("GRANDPA: Cast prevote for block $best_block_number")
            end
        end

        # Cast precommit if we have prevote supermajority
        threshold = supermajority_threshold(service.state)
        prevote_weight = vote_weight(round.prevotes, service.state.validator_weights)

        if prevote_weight >= threshold && !haskey(round.precommits, voter_id)
            if round.prevote_ghost !== nothing
                (ghost_hash, ghost_number) = round.prevote_ghost
                precommit = create_vote(
                    service.state,
                    PRECOMMIT,
                    ghost_hash,
                    ghost_number,
                    service.validator_key
                )

                if precommit !== nothing
                    add_vote!(service.state, precommit)
                    println("GRANDPA: Cast precommit for block $ghost_number")
                end
            end
        end
    end

    # Check for round timeout
    if current_time - service.last_round_start > service.round_timeout
        # Start next round
        next_round = service.state.current_round + 1
        start_round!(service.state, next_round)
        service.last_round_start = current_time
    end

    # Check finalization
    check_finalization!(service.state)
end

# Add incoming vote to service
function add_vote!(service::GrandpaService, vote::GrandpaVote)
    push!(service.pending_votes, vote)
end

export GrandpaVote, GrandpaRound, GrandpaState, GrandpaService,
       VoteType, PREVOTE, PRECOMMIT,
       initialize_grandpa, add_vote!, process_vote!,
       create_vote, is_finalized, get_finalized_block,
       start_grandpa!, stop_grandpa!, grandpa_tick!