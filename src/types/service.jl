# src/types/service.jl
# service account types

struct ServiceAccount
    storage::Dict{Blob, Blob}
    preimages::Dict{Hash, Blob}
    preimage_meta::Dict{Tuple{Hash, UInt32}, Vector{TimeSlot}}
    code_hash::Hash
    balance::Balance
    gas_refine::Gas
    gas_accumulate::Gas
    gratis_offset::Balance
    creation_slot::TimeSlot
    last_accumulation::TimeSlot
    parent_service::ServiceId
    
    # computed fields (cached)
    item_count::UInt32
    octet_count::UInt64
    threshold_balance::Balance
end

# create new service account
function new_service(
    code_hash::Hash,
    balance::Balance,
    gas_refine::Gas,
    gas_accumulate::Gas,
    parent::ServiceId,
    slot::TimeSlot
)::ServiceAccount
    ServiceAccount(
        Dict{Blob, Blob}(),
        Dict{Hash, Blob}(),
        Dict{Tuple{Hash, UInt32}, Vector{TimeSlot}}(),
        code_hash,
        balance,
        gas_refine,
        gas_accumulate,
        0,
        slot,
        0,
        parent,
        0, 0, BS
    )
end

# calculate threshold balance
function compute_threshold(acc::ServiceAccount)::Balance
    items = 2 * length(acc.preimage_meta) + length(acc.storage)
    octets = sum(81 + z for (h, z) in keys(acc.preimage_meta); init=0)
    octets += sum(34 + length(k) + length(v) for (k, v) in acc.storage; init=0)
    
    return max(0, BS + BI * items + BL * octets - acc.gratis_offset)
end
