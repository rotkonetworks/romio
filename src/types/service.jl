# src/types/service.jl
# DEPRECATED: Use src/types/accumulate.jl instead
#
# This file contains an older ServiceAccount definition that is missing fields
# required for full JAM compliance. The unified definition in accumulate.jl includes:
# - min_balance (computed from octets/items)
# - requests (full state machine vs just a set)
# - octets, items, gratis (storage accounting)
# - created, parent (metadata for service lifecycle)
#
# TODO: Migrate all users of this file to accumulate.jl and remove this file

# Include basic types
include("basic.jl")

mutable struct ServiceAccount_DEPRECATED
    storage::Dict{Blob, Blob}
    preimages::Dict{Hash, Blob}
    preimage_meta::Dict{Tuple{Hash, UInt32}, Vector{TimeSlot}}
    code_hash::Hash
    balance::Balance
    threshold_gas::Gas
    min_gas_limit::Gas
    last_accumulation::TimeSlot
    preimage_requests::Set{Hash}
end

# create new service account
function new_service(
    code_hash::Hash,
    balance::Balance,
    threshold_gas::Gas,
    min_gas_limit::Gas
)::ServiceAccount
    ServiceAccount(
        Dict{Blob, Blob}(),
        Dict{Hash, Blob}(),
        Dict{Tuple{Hash, UInt32}, Vector{TimeSlot}}(),
        code_hash,
        balance,
        threshold_gas,
        min_gas_limit,
        0,
        Set{Hash}()
    )
end

# calculate threshold balance
function compute_threshold(acc::ServiceAccount)::Balance
    items = 2 * length(acc.preimage_meta) + length(acc.storage)
    octets = sum(81 + z for (h, z) in keys(acc.preimage_meta); init=0)
    octets += sum(34 + length(k) + length(v) for (k, v) in acc.storage; init=0)
    
    return max(0, BS + BI * items + BL * octets - acc.gratis_offset)
end
