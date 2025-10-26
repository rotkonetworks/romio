# Block production engine

include("safrole.jl")
include("../state/state.jl")
include("../state/transition.jl")
include("../state/validation.jl")
include("../blocks/block.jl")

# Block production context
mutable struct ProductionContext
    validator_key::ValidatorKey
    state::State
    pending_extrinsics::Dict{Symbol, Vector}
    wall_clock::Function  # () -> Float64
end

# Extrinsic pool for collecting transactions
mutable struct ExtrinsicPool
    tickets::Vector{Tuple{UInt32, BandersnatchProof}}
    preimages::Vector{Tuple{ServiceId, Blob}}
    guarantees::Vector{Guarantee}
    assurances::Vector{Assurance}
    disputes::DisputeExtrinsic
end

function ExtrinsicPool()
    ExtrinsicPool(
        Vector{Tuple{UInt32, BandersnatchProof}}(),
        Vector{Tuple{ServiceId, Blob}}(),
        Vector{Guarantee}(),
        Vector{Assurance}(),
        DisputeExtrinsic([], [], [])
    )
end

# Check if validator should produce block at timeslot
function should_produce_block(
    context::ProductionContext,
    target_timeslot::TimeSlot
)::Bool
    # Check if we're the designated author
    can_author = can_author_block(
        context.state.safrole,
        context.validator_key,
        target_timeslot
    )

    if !can_author
        return false
    end

    # Check timing
    return can_author_now(context.wall_clock(), target_timeslot)
end

# Build block extrinsic from pool
function build_extrinsic(
    pool::ExtrinsicPool,
    state::State,
    timeslot::TimeSlot
)::Extrinsic
    # Filter valid tickets (not in tail period)
    valid_tickets = if (timeslot % E) < (E - Y)
        pool.tickets
    else
        Tuple{UInt32, BandersnatchProof}[]
    end

    # Validate and filter guarantees
    valid_guarantees = Vector{Guarantee}()
    for guarantee in pool.guarantees
        # Check if core is available
        core = guarantee.report.core_index
        if core <= C && state.pending_reports[core] === nothing
            # Check if authorizer is in pool
            if guarantee.report.authorizer_hash in state.authorizations[core]
                push!(valid_guarantees, guarantee)
            end
        end
    end

    # Build assurances from validator's view
    valid_assurances = filter_valid_assurances(pool.assurances, state)

    Extrinsic(
        TicketExtrinsic(valid_tickets),
        PreimageExtrinsic(pool.preimages),
        GuaranteeExtrinsic(valid_guarantees),
        AssuranceExtrinsic(valid_assurances),
        pool.disputes
    )
end

# Filter valid assurances
function filter_valid_assurances(
    assurances::Vector{Assurance},
    state::State
)::Vector{Assurance}
    valid = Vector{Assurance}()

    for assurance in assurances
        # Check validator index is valid
        if assurance.validator_index <= length(state.current_validators)
            # Verify signature (simplified)
            validator = state.current_validators[assurance.validator_index]
            if verify_assurance_signature(assurance, validator.ed25519)
                push!(valid, assurance)
            end
        end
    end

    return valid
end

# Verify assurance signature (simplified)
function verify_assurance_signature(assurance::Assurance, ed25519_key::Ed25519Key)::Bool
    # In real implementation, would verify Ed25519 signature
    # For now, always return true
    return true
end

# Produce new block
function produce_block(
    context::ProductionContext,
    pool::ExtrinsicPool,
    target_timeslot::TimeSlot
)::Union{Nothing, Block}
    # Check if we should produce
    if !should_produce_block(context, target_timeslot)
        return nothing
    end

    # Get parent block info
    parent_hash = if isempty(context.state.recent_blocks)
        H0
    else
        context.state.recent_blocks[end].header_hash
    end

    parent_state_root = if isempty(context.state.recent_blocks)
        H0
    else
        context.state.recent_blocks[end].state_root
    end

    # Build extrinsic
    extrinsic = build_extrinsic(pool, context.state, target_timeslot)

    # Calculate extrinsics hash
    extrinsics_hash = H(encode(extrinsic))

    # Determine epoch marker
    epoch_marker = if target_timeslot % E == 0
        H(encode(target_timeslot ÷ E))
    else
        nothing
    end

    # Create header without seal
    header_partial = Header(
        parent_hash = parent_hash,
        parent_state_root = parent_state_root,
        extrinsics_hash = extrinsics_hash,
        timeslot = target_timeslot,
        epoch_marker = epoch_marker,
        tickets_marker = nothing,  # TODO: implement tickets marker
        seal = zeros(64),  # placeholder
        author = context.validator_key.ed25519,
        vrf_signature = BandersnatchSig(zeros(96))  # placeholder
    )

    # Create VRF signature
    vrf_sig = create_vrf_signature(
        context.validator_key,
        context.state.entropy[3],
        target_timeslot
    )

    # Update header with VRF
    header_with_vrf = Header(
        parent_hash = header_partial.parent_hash,
        parent_state_root = header_partial.parent_state_root,
        extrinsics_hash = header_partial.extrinsics_hash,
        timeslot = header_partial.timeslot,
        epoch_marker = header_partial.epoch_marker,
        tickets_marker = header_partial.tickets_marker,
        seal = header_partial.seal,
        author = header_partial.author,
        vrf_signature = vrf_sig
    )

    # Create seal signature
    header_without_seal = encode_header_without_seal(header_with_vrf)
    seal_key = get_seal_key(context.state.safrole, target_timeslot)

    if seal_key === nothing
        return nothing
    end

    entry_index = if isa(seal_key, SafroleTicket)
        seal_key.entry_index
    else
        UInt32(0)
    end

    seal_sig = create_seal_signature(
        context.validator_key,
        header_without_seal,
        context.state.entropy[3],
        entry_index
    )

    # Final header with seal
    header = Header(
        parent_hash = header_with_vrf.parent_hash,
        parent_state_root = header_with_vrf.parent_state_root,
        extrinsics_hash = header_with_vrf.extrinsics_hash,
        timeslot = header_with_vrf.timeslot,
        epoch_marker = header_with_vrf.epoch_marker,
        tickets_marker = header_with_vrf.tickets_marker,
        seal = seal_sig.data[1:64],  # truncate to 64 bytes
        author = header_with_vrf.author,
        vrf_signature = header_with_vrf.vrf_signature
    )

    # Create block
    block = Block(header, extrinsic)

    # Validate block before returning
    valid, msg = validate_block(context.state, block)
    if !valid
        println("Block validation failed: $msg")
        return nothing
    end

    return block
end

# Create VRF signature
function create_vrf_signature(
    validator::ValidatorKey,
    entropy::Hash,
    timeslot::TimeSlot
)::BandersnatchSig
    # VRF input: entropy + timeslot
    message = vcat(entropy, reinterpret(UInt8, [timeslot]))

    # Create deterministic but unpredictable output
    output = H(vcat(validator.bandersnatch, message))

    # Return as signature (simplified)
    return BandersnatchSig(vcat(output, zeros(UInt8, 64)))
end

# Encode header without seal field
function encode_header_without_seal(header::Header)::Vector{UInt8}
    # Serialize all fields except seal
    io = IOBuffer()
    write(io, header.parent_hash)
    write(io, header.parent_state_root)
    write(io, header.extrinsics_hash)
    write(io, header.timeslot)

    if header.epoch_marker !== nothing
        write(io, UInt8(1))
        write(io, header.epoch_marker)
    else
        write(io, UInt8(0))
    end

    if header.tickets_marker !== nothing
        write(io, UInt8(1))
        write(io, header.tickets_marker)
    else
        write(io, UInt8(0))
    end

    write(io, header.author)
    write(io, header.vrf_signature.data)

    return take!(io)
end

# Block production service
mutable struct BlockProducer
    context::ProductionContext
    pool::ExtrinsicPool
    running::Bool
    produced_blocks::Vector{Block}
end

function BlockProducer(validator_key::ValidatorKey, initial_state::State)
    context = ProductionContext(
        validator_key,
        initial_state,
        Dict{Symbol, Vector}(),
        () -> time()  # wall clock function
    )

    BlockProducer(context, ExtrinsicPool(), false, Vector{Block}())
end

# Start block production
function start_production!(producer::BlockProducer)
    producer.running = true
    println("Block production started for validator: $(producer.context.validator_key.ed25519)")
end

# Stop block production
function stop_production!(producer::BlockProducer)
    producer.running = false
    println("Block production stopped")
end

# Production tick - check if should produce block
function production_tick!(producer::BlockProducer)::Union{Nothing, Block}
    if !producer.running
        return nothing
    end

    # Get next timeslot to produce
    current_time = producer.context.wall_clock()
    jam_epoch_start = 1735732800.0  # JAM Common Era start
    seconds_since_epoch = current_time - jam_epoch_start
    target_timeslot = floor(Int, seconds_since_epoch / 6.0) + 1

    # Try to produce block
    block = produce_block(producer.context, producer.pool, target_timeslot)

    if block !== nothing
        push!(producer.produced_blocks, block)
        println("Produced block for timeslot: $target_timeslot")

        # Update state with our own block
        producer.context.state = state_transition(producer.context.state, block)

        # Clear used extrinsics from pool
        clear_used_extrinsics!(producer.pool, block.extrinsic)
    end

    return block
end

# Clear used extrinsics from pool
function clear_used_extrinsics!(pool::ExtrinsicPool, extrinsic::Extrinsic)
    # Remove used tickets
    for ticket in extrinsic.tickets.entries
        filter!(t -> t != ticket, pool.tickets)
    end

    # Remove used guarantees
    for guarantee in extrinsic.guarantees.guarantees
        filter!(g -> g != guarantee, pool.guarantees)
    end

    # Remove used preimages
    for preimage in extrinsic.preimages.preimages
        filter!(p -> p != preimage, pool.preimages)
    end

    # Remove used assurances
    for assurance in extrinsic.assurances.assurances
        filter!(a -> a != assurance, pool.assurances)
    end
end

# Add extrinsic to pool
function add_to_pool!(pool::ExtrinsicPool, ticket::Tuple{UInt32, BandersnatchProof})
    push!(pool.tickets, ticket)
end

function add_to_pool!(pool::ExtrinsicPool, preimage::Tuple{ServiceId, Blob})
    push!(pool.preimages, preimage)
end

function add_to_pool!(pool::ExtrinsicPool, guarantee::Guarantee)
    push!(pool.guarantees, guarantee)
end

function add_to_pool!(pool::ExtrinsicPool, assurance::Assurance)
    push!(pool.assurances, assurance)
end

export ProductionContext, ExtrinsicPool, BlockProducer,
       should_produce_block, produce_block, start_production!,
       stop_production!, production_tick!, add_to_pool!