# Safrole block production mechanism

include("../types/basic.jl")
include("../types/validator.jl")
include("../crypto/hash.jl")

# Safrole ticket structure
struct SafroleTicket
    identifier::Hash
    entry_index::UInt32
end

# Seal key types - either tickets or bandersnatch keys
const SealKey = Union{SafroleTicket, BandersnatchKey}

# Enhanced Safrole state
mutable struct SafroleState
    pending_validators::Vector{ValidatorKey}
    epoch_root::Hash
    seal_keys::Vector{SealKey}
    ticket_accumulator::Vector{SafroleTicket}

    # Additional state for block production
    current_epoch::UInt32
    current_slot_in_epoch::UInt32
    fallback_mode::Bool
end

# Initialize Safrole state
function initialize_safrole(validators::Vector{ValidatorKey})::SafroleState
    # Compute initial ring root
    ring_root = compute_ring_root(validators)

    SafroleState(
        validators,
        ring_root,
        Vector{SealKey}(),
        Vector{SafroleTicket}(),
        0,
        0,
        true  # start in fallback mode
    )
end

# Get current slot's seal key
function get_seal_key(safrole::SafroleState, timeslot::TimeSlot)::Union{Nothing, SealKey}
    slot_in_epoch = timeslot % E

    if slot_in_epoch < length(safrole.seal_keys)
        return safrole.seal_keys[slot_in_epoch + 1]  # 1-indexed
    end

    return nothing
end

# Check if validator can author block at timeslot
function can_author_block(
    safrole::SafroleState,
    validator::ValidatorKey,
    timeslot::TimeSlot
)::Bool
    seal_key = get_seal_key(safrole, timeslot)

    if seal_key === nothing
        return false
    end

    if isa(seal_key, BandersnatchKey)
        # Fallback mode - direct key comparison
        return seal_key == validator.bandersnatch
    else
        # Ticket mode - would need to verify ring VRF proof
        # For now, simplified check
        return true
    end
end

# Generate block seal signature
function create_seal_signature(
    validator::ValidatorKey,
    header_without_seal::Vector{UInt8},
    entropy::Hash,
    entry_index::UInt32
)::BandersnatchSig
    # Construct message for signing
    message = vcat(
        [0x54, 0x49, 0x43, 0x4b],  # "TICK" prefix
        entropy,
        reinterpret(UInt8, [entry_index])
    )

    # In real implementation, would use proper Bandersnatch signing
    # For now, return placeholder signature
    return BandersnatchSig(vcat(message[1:min(96, length(message))], zeros(UInt8, max(0, 96 - length(message)))))
end

# Verify block seal
function verify_seal(
    header::Header,
    safrole::SafroleState,
    author_key::BandersnatchKey
)::Bool
    seal_key = get_seal_key(safrole, header.timeslot)

    if seal_key === nothing
        return false
    end

    if isa(seal_key, BandersnatchKey)
        # Fallback mode - verify direct key
        return seal_key == author_key
    else
        # Ticket mode - verify ring VRF proof
        # Simplified verification for now
        ticket = seal_key::SafroleTicket
        expected_id = banderout(header.seal)
        return ticket.identifier == expected_id
    end
end

# Process incoming tickets
function process_tickets!(
    safrole::SafroleState,
    tickets::TicketExtrinsic,
    timeslot::TimeSlot,
    entropy::Hash
)
    # Only process tickets before tail period
    slot_in_epoch = timeslot % E
    if slot_in_epoch >= E - Y
        return
    end

    # Add new valid tickets
    for (attempt, proof) in tickets.entries
        # Verify ring VRF proof
        if verify_ring_vrf_proof(proof, safrole.epoch_root, entropy)
            ticket_id = banderout(proof.data)
            new_ticket = SafroleTicket(ticket_id, attempt)
            push!(safrole.ticket_accumulator, new_ticket)
        end
    end

    # Sort tickets by identifier (best tickets have lowest ID)
    sort!(safrole.ticket_accumulator, by=t -> t.identifier)

    # Keep only best E tickets
    if length(safrole.ticket_accumulator) > E
        resize!(safrole.ticket_accumulator, E)
    end
end

# Epoch transition
function epoch_transition!(
    safrole::SafroleState,
    new_validators::Vector{ValidatorKey},
    offenders::Set{Ed25519Key}
)
    # Filter out offenders
    filtered_validators = filter_offending_validators(new_validators, offenders)

    # Update validator sets
    safrole.pending_validators = filtered_validators

    # Update epoch root
    safrole.epoch_root = compute_ring_root(filtered_validators)

    # Determine seal keys for new epoch
    if length(safrole.ticket_accumulator) >= E
        # Use tickets
        safrole.seal_keys = Vector{SealKey}(safrole.ticket_accumulator[1:E])
        safrole.fallback_mode = false
    else
        # Fallback to validator keys
        validator_keys = [v.bandersnatch for v in filtered_validators]
        # Extend/repeat keys to fill epoch
        seal_keys = Vector{SealKey}()
        for i in 1:E
            key_index = ((i - 1) % length(validator_keys)) + 1
            push!(seal_keys, validator_keys[key_index])
        end
        safrole.seal_keys = seal_keys
        safrole.fallback_mode = true
    end

    # Reset ticket accumulator
    empty!(safrole.ticket_accumulator)

    # Update epoch counter
    safrole.current_epoch += 1
end

# Filter validators removing offenders
function filter_offending_validators(
    validators::Vector{ValidatorKey},
    offenders::Set{Ed25519Key}
)::Vector{ValidatorKey}
    return [
        v.ed25519 in offenders ?
        ValidatorKey(zeros(32), zeros(32), zeros(144)) :  # null key
        v
        for v in validators
    ]
end

# Simplified ring VRF verification
function verify_ring_vrf_proof(
    proof::BandersnatchProof,
    ring_root::Hash,
    entropy::Hash
)::Bool
    # In real implementation, would verify Bandersnatch ring VRF
    # For now, simplified check
    return length(proof.data.data) == 96
end

# Extract VRF output from signature
function banderout(sig::BandersnatchSig)::Hash
    # Extract deterministic output from signature
    return H(sig.data[1:32])
end

# Get next block author for timeslot
function get_block_author(
    safrole::SafroleState,
    validators::Vector{ValidatorKey},
    timeslot::TimeSlot
)::Union{Nothing, ValidatorKey}
    seal_key = get_seal_key(safrole, timeslot)

    if seal_key === nothing
        return nothing
    end

    if isa(seal_key, BandersnatchKey)
        # Fallback mode - find validator with matching key
        for validator in validators
            if validator.bandersnatch == seal_key
                return validator
            end
        end
    else
        # Ticket mode - would need more complex mapping
        # For now, return first validator as placeholder
        if !isempty(validators)
            return validators[1]
        end
    end

    return nothing
end

# Check if current time allows block authoring
function can_author_now(wall_clock_time::Float64, target_timeslot::TimeSlot)::Bool
    # JAM Common Era started at 1200 UTC on January 1, 2025
    jam_epoch_start = 1735732800.0  # Unix timestamp

    # Calculate target time
    target_time = jam_epoch_start + (target_timeslot * 6.0)  # 6 second slots

    # Allow authoring slightly before target time (for network latency)
    return wall_clock_time >= (target_time - 1.0)
end

export SafroleState, SafroleTicket, SealKey,
       initialize_safrole, get_seal_key, can_author_block,
       create_seal_signature, verify_seal, process_tickets!,
       epoch_transition!, get_block_author, can_author_now