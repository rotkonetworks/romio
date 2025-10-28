# src/types/accumulate.jl
# Unified types for accumulate phase - consolidates host_calls.jl and types/service.jl

include("basic.jl")

"""
Preimage request state machine per graypaper Section 13.2.7
- []: empty - request exists but not satisfied
- [x]: partial - requester paid x gas at submission
- [x, y]: pending - paid x gas, finalized at timeslot y
- [x, y, z]: available - paid x gas, finalized at y, re-requested at z
"""
mutable struct PreimageRequest
    state::Vector{UInt64}  # 0-3 elements
end

"""
Deferred transfer - balance transfer with memo per graypaper Section 13.2.5
"""
struct DeferredTransfer
    source::ServiceId
    dest::ServiceId
    amount::Balance
    memo::Blob  # Cmemosize (128) bytes
    gas::Gas
end

"""
Service account - complete JAM service state per graypaper Section 3.4
Unified from host_calls.jl (more complete) and types/service.jl
"""
mutable struct ServiceAccount
    # Code and storage
    code_hash::Blob  # 32 bytes - service code hash
    storage::Dict{Blob, Blob}  # key => value storage

    # Preimages
    preimages::Dict{Blob, Blob}  # hash => preimage data
    requests::Dict{Tuple{Blob, UInt64}, PreimageRequest}  # (hash, length) => request state

    # Balance and gas
    balance::Balance  # current balance
    min_balance::Balance  # minimum balance to maintain (computed from octets/items)
    min_acc_gas::Gas  # minimum gas for accumulate invocation
    min_memo_gas::Gas  # minimum gas for on-transfer invocation

    # Storage accounting
    octets::UInt64  # total storage bytes used
    items::UInt32   # number of storage items (requests + storage entries)
    gratis::UInt64  # gratis offset (free storage allowance)

    # Metadata
    created::TimeSlot  # timeslot when service was created
    last_acc::TimeSlot  # timeslot of last accumulation
    parent::ServiceId  # parent service ID (for ejection)
end

"""
Create new service account with default values
"""
function ServiceAccount(
    code_hash::Blob,
    balance::Balance,
    min_acc_gas::Gas,
    min_memo_gas::Gas;
    gratis::UInt64 = 0,
    created::TimeSlot = 0,
    parent::ServiceId = 0
)
    ServiceAccount(
        code_hash,
        Dict{Blob, Blob}(),                                # storage
        Dict{Blob, Blob}(),                                # preimages
        Dict{Tuple{Blob, UInt64}, PreimageRequest}(),     # requests
        balance,
        0,                                                  # min_balance (computed)
        min_acc_gas,
        min_memo_gas,
        0,                                                  # octets
        0,                                                  # items
        gratis,
        created,
        0,                                                  # last_acc
        parent
    )
end

"""
Privileged state - chain-level configuration per graypaper Section 13.2.1
Manages special services that control chain parameters
"""
mutable struct PrivilegedState
    manager::ServiceId  # service that can bless (update privileged services)
    assigners::Vector{ServiceId}  # per-core: service that assigned work to this core
    delegator::ServiceId  # service that can designate (update validator set)
    registrar::ServiceId  # service that can create privileged services (ID < 2^16)
    staging_set::Vector{Blob}  # validator staging set (Cvalcount entries of 336 bytes)
    auth_queue::Vector{Vector{Blob}}  # per-core auth queues (Ccorecount x Cauthqueuesize)
    always_access::Vector{Tuple{ServiceId, Gas}}  # services with permanent accumulate access
end

"""
Create empty privileged state with defaults
"""
function PrivilegedState()
    PrivilegedState(
        UInt32(0),          # manager
        UInt32[],           # assigners (per-core)
        UInt32(0),          # delegator
        UInt32(0),          # registrar
        Vector{Blob}(),     # staging_set
        Vector{Vector{Blob}}(),  # auth_queue (per-core)
        Vector{Tuple{ServiceId, Gas}}()  # always_access
    )
end

"""
Implications context - mutable state tracking per graypaper Section 13
Represents imX (normal exit) and imY (exceptional exit)
"""
mutable struct ImplicationsContext
    service_id::ServiceId  # current service being executed

    # Service state (imX for normal exit, imY for exceptional)
    self::ServiceAccount  # current service's account

    # Global state (shared across services in this accumulation)
    privileged_state::PrivilegedState
    accounts::Dict{ServiceId, ServiceAccount}  # all service accounts

    # Accumulation outputs
    transfers::Vector{DeferredTransfer}  # deferred transfers (xfers)
    provisions::Set{Tuple{ServiceId, Blob}}  # (service_id, preimage_data)
    yield_hash::Union{Blob, Nothing}  # result hash (32 bytes or nothing)

    # State management
    next_free_id::ServiceId  # next available service ID
    current_time::TimeSlot  # current timeslot

    # Checkpoint support for exceptional exits
    exceptional_state::Union{ImplicationsContext, Nothing}  # imY - checkpointed state
end

"""
Create implications context for a service invocation
"""
function ImplicationsContext(
    service_id::ServiceId,
    self::ServiceAccount,
    accounts::Dict{ServiceId, ServiceAccount},
    privileged_state::PrivilegedState,
    current_time::TimeSlot;
    next_free_id::ServiceId = UInt32(2^16)  # Start from Cminpublicindex
)
    ImplicationsContext(
        service_id,
        self,
        privileged_state,
        accounts,
        DeferredTransfer[],
        Set{Tuple{ServiceId, Blob}}(),
        nothing,
        next_free_id,
        current_time,
        nothing  # no checkpoint initially
    )
end

"""
Host call context - contains state for host call execution
For accumulate invocations, contains ImplicationsContext
"""
struct HostCallContext
    service_id::ServiceId

    # Implications context for accumulate invocations (mutable state tracking)
    implications::Union{ImplicationsContext, Nothing}

    # Environment data for fetch host call
    entropy::Union{Blob, Nothing}  # 32-byte entropy/timeslot hash
    config::Union{Dict{Symbol, Any}, Nothing}  # JAM configuration constants
    work_package::Union{Dict{Symbol, Any}, Nothing}  # Work package data
    recent_blocks::Union{Vector{Blob}, Nothing}  # Recent block hashes
end

"""
Constructor for accumulate invocations with implications context
"""
function HostCallContext(
    implications::ImplicationsContext,
    entropy::Union{Blob, Nothing} = nothing,
    config::Union{Dict{Symbol, Any}, Nothing} = nothing,
    work_package::Union{Dict{Symbol, Any}, Nothing} = nothing,
    recent_blocks::Union{Vector{Blob}, Nothing} = nothing
)
    HostCallContext(
        implications.service_id,
        implications,
        entropy,
        config,
        work_package,
        recent_blocks
    )
end

"""
Constructor for non-accumulate invocations (refine, on-transfer)
"""
function HostCallContext(
    service_id::ServiceId;
    entropy::Union{Blob, Nothing} = nothing,
    config::Union{Dict{Symbol, Any}, Nothing} = nothing,
    work_package::Union{Dict{Symbol, Any}, Nothing} = nothing,
    recent_blocks::Union{Vector{Blob}, Nothing} = nothing
)
    HostCallContext(
        service_id,
        nothing,  # no implications
        entropy,
        config,
        work_package,
        recent_blocks
    )
end

# Export all types
export PreimageRequest, DeferredTransfer, ServiceAccount, PrivilegedState
export ImplicationsContext, HostCallContext
export Balance, Gas, ServiceId, TimeSlot, Blob, Hash
