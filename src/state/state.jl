# src/state/state.jl
# Main state structure

mutable struct State
    # Core authorizations (α, φ)
    authorizations::Vector{Vector{Hash}}      # C cores
    auth_queue::Vector{Vector{Hash}}          # C cores × Q items
    
    # Recent history (β)
    recent_blocks::Vector{RecentBlock}
    accumulation_log::MerkleMountainBelt
    
    # Safrole state (γ)
    safrole::SafroleState
    
    # Service accounts (δ)
    services::Dict{ServiceId, ServiceAccount}
    
    # Disputes and judgments (ψ)
    judgments::JudgmentState
    
    # Entropy (η)
    entropy::NTuple{4, Hash}
    
    # Validator keys (ι, κ, λ)
    queued_validators::Vector{ValidatorKey}
    current_validators::Vector{ValidatorKey}
    previous_validators::Vector{ValidatorKey}
    
    # Pending reports (ρ)
    pending_reports::Vector{Union{Nothing, Tuple{WorkReport, TimeSlot}}}
    
    # Timeslot (τ)
    timeslot::TimeSlot
    
    # Privileges (χ)
    privileges::PrivilegeState
    
    # Statistics (π)
    statistics::StatisticsState
    
    # Accumulation queue (ω)
    accumulation_queue::Vector{Vector{Tuple{WorkReport, Set{Hash}}}}
    
    # Accumulation history (ξ)
    accumulation_history::Vector{Set{Hash}}
    
    # Recent outputs (θ)
    recent_outputs::Vector{Tuple{ServiceId, Hash}}
end

struct RecentBlock
    header_hash::Hash
    state_root::Hash
    accumulation_root::Hash
    work_packages::Dict{Hash, Hash}
end

struct SafroleState
    pending::Vector{ValidatorKey}
    ring_root::Hash
    seal_keys::Union{Vector{Ticket}, Vector{BandersnatchKey}}
    ticket_accumulator::Vector{Ticket}
end

struct JudgmentState
    good_reports::Set{Hash}
    bad_reports::Set{Hash}
    wonky_reports::Set{Hash}
    offenders::Set{Ed25519Key}
end

struct PrivilegeState
    manager::ServiceId
    validator_designator::ServiceId
    registrar::ServiceId
    core_assigners::Vector{ServiceId}
    auto_accumulate::Dict{ServiceId, Gas}
end

struct StatisticsState
    validator_stats::Tuple{Vector{ValidatorStats}, Vector{ValidatorStats}}
    core_stats::Vector{CoreStats}
    service_stats::Dict{ServiceId, ServiceStats}
end
