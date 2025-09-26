# src/codec/jam_types.jl
# JAM-specific type encoding

module JAMCodec

using ..Codec
using ..ComplexCodec
using StaticArrays

# ===== JAM Basic Types =====

# Hash (32 bytes) - identity encoding
encode(h::SVector{32, UInt8}) = collect(h)

# Service ID (u32)
encode(id::UInt32) = Codec.encode_u32(id)

# Balance/Gas (u64)
encode(balance::UInt64) = Codec.encode_u64(balance)

# Work error encoding
function encode_error(err::Symbol)
    if err == :out_of_gas
        return [0x01]
    elseif err == :panic
        return [0x02]
    elseif err == :bad_export_count
        return [0x03]
    elseif err == :bad_import
        return [0x04]
    elseif err == :bad_code
        return [0x05]
    elseif err == :code_too_large
        return [0x06]
    else
        error("Unknown error type: $err")
    end
end

# Work result (blob or error)
function encode_work_result(result::Union{Vector{UInt8}, Symbol})
    if isa(result, Symbol)
        return encode_error(result)
    else
        return [0x00, ComplexCodec.encode_with_length(result)...]
    end
end

# ===== Work Structures =====

# Work item encoding
function encode_work_item(item)
    result = UInt8[]
    append!(result, Codec.encode_u32(item.service))
    append!(result, encode(item.code_hash))
    append!(result, Codec.encode_u64(item.gas_refine))
    append!(result, Codec.encode_u64(item.gas_accumulate))
    append!(result, Codec.encode_u16(item.export_count))
    append!(result, ComplexCodec.encode_with_length(item.payload))
    
    # encode imports with tagged unions
    append!(result, ComplexCodec.encode_with_length(item.imports))
    
    # encode extrinsics
    for (hash, len) in item.extrinsics
        append!(result, encode(hash))
        append!(result, Codec.encode_u32(len))
    end
    
    return result
end

# Work package encoding
function encode_work_package(pkg)
    result = UInt8[]
    append!(result, Codec.encode_u32(pkg.auth_service))
    append!(result, encode(pkg.auth_code_hash))
    append!(result, encode_context(pkg.context))
    append!(result, ComplexCodec.encode_with_length(pkg.authorization_token))
    append!(result, ComplexCodec.encode_with_length(pkg.auth_config))
    append!(result, ComplexCodec.encode_with_length(pkg.items))
    return result
end

# Work report encoding
function encode_work_report(report)
    result = UInt8[]
    append!(result, encode(report.specification))
    append!(result, encode_context(report.context))
    append!(result, Codec.encode_u16(report.core_index))
    append!(result, encode(report.authorizer_hash))
    append!(result, Codec.encode_u64(report.gas_used))
    append!(result, ComplexCodec.encode_with_length(report.trace))
    append!(result, ComplexCodec.encode_with_length(collect(report.segment_roots)))
    append!(result, ComplexCodec.encode_with_length(report.digests))
    return result
end

# Work digest encoding
function encode_work_digest(digest)
    result = UInt8[]
    append!(result, Codec.encode_u32(digest.service))
    append!(result, encode(digest.code_hash))
    append!(result, encode(digest.payload_hash))
    append!(result, Codec.encode_u64(digest.gas_accumulate))
    append!(result, encode_work_result(digest.result))
    append!(result, Codec.encode(digest.gas_used))
    append!(result, Codec.encode(digest.imports_count))
    append!(result, Codec.encode(digest.exports_count))
    append!(result, Codec.encode(digest.extrinsics_count))
    append!(result, Codec.encode(digest.extrinsics_size))
    return result
end

# Context encoding
function encode_context(ctx)
    result = UInt8[]
    append!(result, encode(ctx.anchor))
    append!(result, encode(ctx.state_root))
    append!(result, encode(ctx.accumulation_root))
    append!(result, encode(ctx.lookup_anchor))
    append!(result, Codec.encode_u32(ctx.lookup_slot))
    append!(result, ComplexCodec.encode_with_length(ctx.prerequisites))
    return result
end

# ===== Block Structures =====

# Header encoding (unsigned version for signatures)
function encode_header_unsigned(header)
    result = UInt8[]
    append!(result, encode(header.parent_hash))
    append!(result, encode(header.state_root))
    append!(result, encode(header.extrinsic_hash))
    append!(result, Codec.encode_u32(header.timeslot))
    append!(result, ComplexCodec.encode_option(header.epoch_marker))
    append!(result, ComplexCodec.encode_option(header.winning_tickets))
    append!(result, Codec.encode_u16(header.author_index))
    append!(result, encode(header.vrf_signature))
    append!(result, ComplexCodec.encode_with_length(header.offenders))
    return result
end

# Full header encoding
function encode_header(header)
    result = encode_header_unsigned(header)
    append!(result, encode(header.seal))
    return result
end

export encode, encode_error, encode_work_result
export encode_work_item, encode_work_package, encode_work_report, encode_work_digest
export encode_context, encode_header, encode_header_unsigned

end # module JAMCodec
