# src/blocks/header.jl
# Block header structure

struct Header
    parent_hash::Hash
    state_root::Hash
    extrinsic_hash::Hash
    timeslot::TimeSlot
    epoch_marker::Union{Nothing, EpochMarker}
    winning_tickets::Union{Nothing, Vector{Ticket}}
    offenders::Vector{Ed25519Key}
    author_index::ValidatorId
    vrf_signature::BandersnatchSig
    seal::BandersnatchSig
end

struct EpochMarker
    entropy::Hash
    previous_entropy::Hash
    validators::Vector{Tuple{BandersnatchKey, Ed25519Key}}
end

function validate_header(header::Header, parent::Header, state::State)::Bool
    # Check timeslot
    if header.timeslot <= parent.timeslot
        return false
    end
    
    if header.timeslot * P > current_time()
        return false
    end
    
    # Check parent hash
    if header.parent_hash != hash_header(parent)
        return false
    end
    
    # Validate seal signature
    seal_key = state.safrole.seal_keys[header.timeslot % E]
    if !verify_seal(header, seal_key)
        return false
    end
    
    return true
end
