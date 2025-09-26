# src/state/state.jl
# main state structure

using StaticArrays
using DataStructures

# include merkle mountain range

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



mutable struct State
   # core authorizations (α, φ)
   authorizations::Vector{Vector{Hash}}
   auth_queue::Vector{Vector{Hash}}
   
   # recent history (β)
   recent_blocks::Vector{RecentBlock}
   accumulation_log::MerkleMountainBelt
   
   # safrole state (γ)
   safrole::SafroleState
   
   # service accounts (δ)
   services::Dict{ServiceId, ServiceAccount}
   
   # disputes and judgments (ψ)
   judgments::JudgmentState
   
   # entropy (η)
   entropy::NTuple{4, Hash}
   
   # validator keys (ι, κ, λ)
   queued_validators::Vector{ValidatorKey}
   current_validators::Vector{ValidatorKey}
   previous_validators::Vector{ValidatorKey}
   
   # pending reports (ρ)
   pending_reports::Vector{Union{Nothing, Tuple{WorkReport, TimeSlot}}}
   
   # timeslot (τ)
   timeslot::TimeSlot
   
   # privileges (χ)
   privileges::PrivilegeState
   
   # statistics (π)
   statistics::StatisticsState
   
   # accumulation queue (ω)
   accumulation_queue::Vector{Vector{Tuple{WorkReport, Set{Hash}}}}
   
   # accumulation history (ξ)
   accumulation_history::Vector{Set{Hash}}
   
   # recent outputs (θ)
   recent_outputs::Vector{Tuple{ServiceId, Hash}}
end

# create initial empty state
function initial_state()::State
   State(
       # authorizations
       [Vector{Hash}() for _ in 1:C],
       [Vector{Hash}() for _ in 1:Q],
       
       # recent blocks
       Vector{RecentBlock}(),
       MerkleMountainBelt(),
       
       # safrole
       SafroleState(
           Vector{ValidatorKey}(),
           H0,
           Vector{BandersnatchKey}(),
           Vector{Ticket}()
       ),
       
       # services
       Dict{ServiceId, ServiceAccount}(),
       
       # judgments
       JudgmentState(
           Set{Hash}(),
           Set{Hash}(),
           Set{Hash}(),
           Set{Ed25519Key}()
       ),
       
       # entropy
       (H0, H0, H0, H0),
       
       # validators
       Vector{ValidatorKey}(),
       Vector{ValidatorKey}(),
       Vector{ValidatorKey}(),
       
       # pending reports
       [nothing for _ in 1:C],
       
       # timeslot
       TimeSlot(0),
       
       # privileges
       PrivilegeState(
           ServiceId(0),
           ServiceId(0),
           ServiceId(0),
           Vector{ServiceId}(),
           Dict{ServiceId, Gas}()
       ),
       
       # statistics
       StatisticsState(
           (Vector{ValidatorStats}(), Vector{ValidatorStats}()),
           [CoreStats(0, 0) for _ in 1:C],
           Dict{ServiceId, ServiceStats}()
       ),
       
       # accumulation queue
       Vector{Vector{Tuple{WorkReport, Set{Hash}}}}(),
       
       # accumulation history
       Vector{Set{Hash}}(),
       
       # recent outputs
       Vector{Tuple{ServiceId, Hash}}()
   )
end

# get accumulation root from belt
function get_accumulation_root(state::State)::Hash
   belt_superpeak(state.accumulation_log)
end

# add accumulation output to state
function add_accumulation_output!(state::State, service::ServiceId, output::Hash)
   # append to merkle mountain belt
   belt_append!(state.accumulation_log, service, output)
   
   # update recent outputs
   push!(state.recent_outputs, (service, output))
   
   # keep only last 1024 outputs
   if length(state.recent_outputs) > 1024
       popfirst!(state.recent_outputs)
   end
end
