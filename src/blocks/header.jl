# src/blocks/header.jl
# block header structure

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
    # check timeslot
    if header.timeslot <= parent.timeslot
        return false
    end
    
    if header.timeslot * P > current_time()
        return false
    end
    
    # check parent hash
    if header.parent_hash != hash_header(parent)
        return false
    end
    
    # validate seal signature
    seal_key = state.safrole.seal_keys[header.timeslot % E]
    if !verify_seal(header, seal_key)
        return false
    end
    
    return true
end
