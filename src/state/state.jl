# src/state/state.jl
# main state structure

using StaticArrays
using DataStructures

# include unified accumulate types (ServiceAccount, PrivilegedState)
include("../types/accumulate.jl")

# include state-specific types (WorkReport, ValidatorKey, etc.)
include("types.jl")

struct RecentBlock
   header_hash::Hash
   state_root::Hash
   accumulation_root::Hash
   reported_packages::Set{Hash}
   seal::Union{Nothing, BandersnatchSig}
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
   punish_set::Set{ValidatorId}
end

# PrivilegedState now imported from types/accumulate.jl
# This provides the complete privileged state with staging_set, auth_queue, etc.
#
# NOTE: The global State uses a simpler representation for some fields.
# When converting to/from ImplicationsContext, we need to handle:
# - validator_designator → delegator
# - core_assigners → assigners
# - auto_accumulate → always_access (different semantics)




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
   pending_reports::Vector{Union{Nothing, PendingReport}}
   
   # timeslot (τ)
   timeslot::TimeSlot
   
   # privileges (χ)
   privileges::PrivilegedState
   
   # statistics (π)
   statistics::StatisticsState
   
   # ready queue (ω)
   ready::Vector{Tuple{WorkReport, Set{Hash}}}

   # accumulated packages (ξ)
   accumulated::Set{Hash}

   # last accumulation results (θ)
   last_accumulation::Vector{AccumulationEntry}
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
           Set{Ed25519Key}(),
           Set{ValidatorId}()
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
       
       # privileges (using PrivilegedState from accumulate.jl)
       PrivilegedState(
           ServiceId(0),           # manager
           Vector{ServiceId}(),    # assigners (per-core)
           ServiceId(0),           # delegator
           ServiceId(0),           # registrar
           Vector{Blob}(),         # staging_set
           Vector{Vector{Blob}}(), # auth_queue
           Vector{Tuple{ServiceId, Gas}}()  # always_access
       ),
       
       # statistics
       StatisticsState(
           (Vector{ValidatorStats}(), Vector{ValidatorStats}()),
           [CoreStats(0, 0) for _ in 1:C],
           Dict{ServiceId, ServiceStats}()
       ),
       
       # ready queue
       Vector{Tuple{WorkReport, Set{Hash}}}(),

       # accumulated packages
       Set{Hash}(),

       # last accumulation
       Vector{AccumulationEntry}()
   )
end

# get accumulation root from belt
function get_accumulation_root(state::State)::Hash
   state.accumulation_log.root
end
