# src/types/work.jl
# work-related types

struct WorkItem
    service::ServiceId
    code_hash::Hash
    payload::Blob
    gas_refine::Gas
    gas_accumulate::Gas
    imports::Vector{Tuple{Union{Hash, Tagged{Hash}}, UInt32}}
    extrinsics::Vector{Tuple{Hash, UInt32}}
    export_count::UInt32
end

struct WorkContext
    anchor::Hash
    state_root::Hash
    accumulation_root::Hash
    lookup_anchor::Hash
    lookup_slot::TimeSlot
    prerequisites::Vector{Hash}
end

struct WorkPackage
    authorization_token::Blob
    auth_service::ServiceId
    auth_code_hash::Hash
    auth_config::Blob
    context::WorkContext
    items::Vector{WorkItem}
end

struct WorkDigest
    service::ServiceId
    code_hash::Hash
    payload_hash::Hash
    gas_accumulate::Gas
    result::Union{Blob, Symbol}  # :out_of_gas, :panic, :bad, :big
    gas_used::Gas
    imports_count::UInt32
    exports_count::UInt32
    extrinsics_count::UInt32
    extrinsics_size::UInt32
end

struct WorkReport
    specification::WorkPackage
    context::WorkContext
    core_index::CoreId
    authorizer_hash::Hash
    trace::Blob
    segment_roots::Dict{Hash, Hash}
    gas_used::Gas
    digests::Vector{WorkDigest}
end

struct AvailabilitySpec
    package_hash::Hash
    bundle_length::UInt32
    erasure_root::Hash
    segment_root::Hash
    segment_count::UInt32
end
