# src/serialization/jam_types.jl
# JAM-specific type encoding
# Optimized with Writer pattern for zero-copy encoding

module JAMCodec

using ..Codec
using ..ComplexCodec
using StaticArrays

export encode, encode_error, encode_work_result
export encode_work_item, encode_work_package, encode_work_report, encode_work_digest
export encode_context, encode_header, encode_header_unsigned

# ===== Size Calculation Functions =====

function size_of_error(err::Symbol)::Int
    return 1  # All errors are 1 byte
end

function size_of_work_result(result::Union{Vector{UInt8}, Symbol})::Int
    if isa(result, Symbol)
        return size_of_error(result)
    else
        return 1 + Codec.size_of_natural(length(result)) + length(result)
    end
end

function size_of_context(ctx)::Int
    size = 32 + 32 + 32 + 32 + 4  # 4 hashes + u32
    size += Codec.size_of_natural(length(ctx.prerequisites))
    size += 32 * length(ctx.prerequisites)
    return size
end

function size_of_work_item(item)::Int
    size = 4 + 32 + 8 + 8 + 2  # Fixed fields

    # Payload
    size += Codec.size_of_natural(length(item.payload))
    size += length(item.payload)

    # Imports
    size += Codec.size_of_natural(length(item.imports))
    for imp in item.imports
        size += length(Codec.encode(imp))  # TODO: optimize this
    end

    # Extrinsics
    size += Codec.size_of_natural(length(item.extrinsics))
    size += length(item.extrinsics) * (32 + 4)

    return size
end

function size_of_work_package(pkg)::Int
    size = 4 + 32  # auth_service + auth_code_hash
    size += size_of_context(pkg.context)
    size += Codec.size_of_natural(length(pkg.authorization_token)) + length(pkg.authorization_token)
    size += Codec.size_of_natural(length(pkg.auth_config)) + length(pkg.auth_config)
    size += Codec.size_of_natural(length(pkg.items))
    for item in pkg.items
        size += length(encode_work_item(item))  # TODO: optimize
    end
    return size
end

function size_of_work_report(report)::Int
    size = 32  # specification hash
    size += size_of_context(report.context)
    size += 2 + 32 + 8  # core_index + authorizer_hash + gas_used
    size += Codec.size_of_natural(length(report.trace)) + length(report.trace)
    size += Codec.size_of_natural(length(report.segment_roots)) + 32 * length(report.segment_roots)
    size += Codec.size_of_natural(length(report.digests))
    for digest in report.digests
        size += length(encode_work_digest(digest))  # TODO: optimize
    end
    return size
end

function size_of_work_digest(digest)::Int
    size = 4 + 32 + 32 + 8  # service + code_hash + payload_hash + gas_accumulate
    size += size_of_work_result(digest.result)
    size += Codec.size_of_natural(digest.gas_used)
    size += Codec.size_of_natural(digest.imports_count)
    size += Codec.size_of_natural(digest.exports_count)
    size += Codec.size_of_natural(digest.extrinsics_count)
    size += Codec.size_of_natural(digest.extrinsics_size)
    return size
end

function size_of_header_unsigned(header)::Int
    size = 32 + 32 + 32 + 4 + 2  # Hashes + timeslot + author_index

    # epoch_marker optional
    size += 1
    if header.epoch_marker !== nothing
        size += length(ComplexCodec.encode(header.epoch_marker))
    end

    # winning_tickets optional
    size += 1
    if header.winning_tickets !== nothing
        size += length(ComplexCodec.encode(header.winning_tickets))
    end

    size += 32  # vrf_signature (assuming 32 bytes)
    size += Codec.size_of_natural(length(header.offenders))
    size += length(header.offenders) * 144  # Assuming 144 bytes per offender

    return size
end

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

# ===== Work Structures Encoding =====

# Context encoding
function encode_context(ctx)
    size = size_of_context(ctx)
    writer = Codec.Writer(size)

    Codec.write_hash!(writer, ctx.anchor)
    Codec.write_hash!(writer, ctx.state_root)
    Codec.write_hash!(writer, ctx.accumulation_root)
    Codec.write_hash!(writer, ctx.lookup_anchor)
    Codec.write_u32!(writer, ctx.lookup_slot)

    # Prerequisites
    Codec.write_natural!(writer, length(ctx.prerequisites))
    for hash in ctx.prerequisites
        Codec.write_hash!(writer, hash)
    end

    return Codec.finalize_writer(writer)
end

# Work item encoding
function encode_work_item(item)
    size = size_of_work_item(item)
    writer = Codec.Writer(size)

    # Fixed fields
    Codec.write_u32!(writer, item.service)
    Codec.write_hash!(writer, item.code_hash)
    Codec.write_u64!(writer, item.gas_refine)
    Codec.write_u64!(writer, item.gas_accumulate)
    Codec.write_u16!(writer, item.export_count)

    # Payload
    Codec.write_blob!(writer, item.payload)

    # Imports - using old method for now (TODO: optimize ComplexCodec)
    imports_encoded = ComplexCodec.encode_with_length(item.imports)
    copyto!(writer.buffer, writer.pos, imports_encoded, 1, length(imports_encoded))
    writer.pos += length(imports_encoded)

    # Extrinsics
    Codec.write_natural!(writer, length(item.extrinsics))
    for (hash, len) in item.extrinsics
        Codec.write_hash!(writer, hash)
        Codec.write_u32!(writer, len)
    end

    return Codec.finalize_writer(writer)
end

# Work package encoding
function encode_work_package(pkg)
    size = size_of_work_package(pkg)
    writer = Codec.Writer(size)

    Codec.write_u32!(writer, pkg.auth_service)
    Codec.write_hash!(writer, pkg.auth_code_hash)

    # Context
    ctx_encoded = encode_context(pkg.context)
    copyto!(writer.buffer, writer.pos, ctx_encoded, 1, length(ctx_encoded))
    writer.pos += length(ctx_encoded)

    # Authorization token and config
    Codec.write_blob!(writer, pkg.authorization_token)
    Codec.write_blob!(writer, pkg.auth_config)

    # Items - using old method for now
    items_encoded = ComplexCodec.encode_with_length(pkg.items)
    copyto!(writer.buffer, writer.pos, items_encoded, 1, length(items_encoded))
    writer.pos += length(items_encoded)

    return Codec.finalize_writer(writer)
end

# Work report encoding
function encode_work_report(report)
    size = size_of_work_report(report)
    writer = Codec.Writer(size)

    Codec.write_hash!(writer, report.specification)

    # Context
    ctx_encoded = encode_context(report.context)
    copyto!(writer.buffer, writer.pos, ctx_encoded, 1, length(ctx_encoded))
    writer.pos += length(ctx_encoded)

    Codec.write_u16!(writer, report.core_index)
    Codec.write_hash!(writer, report.authorizer_hash)
    Codec.write_u64!(writer, report.gas_used)

    # Trace
    Codec.write_blob!(writer, report.trace)

    # Segment roots (remove unnecessary collect!)
    Codec.write_natural!(writer, length(report.segment_roots))
    for root in report.segment_roots
        Codec.write_hash!(writer, root)
    end

    # Digests - using old method for now
    digests_encoded = ComplexCodec.encode_with_length(report.digests)
    copyto!(writer.buffer, writer.pos, digests_encoded, 1, length(digests_encoded))
    writer.pos += length(digests_encoded)

    return Codec.finalize_writer(writer)
end

# Work digest encoding
function encode_work_digest(digest)
    size = size_of_work_digest(digest)
    writer = Codec.Writer(size)

    Codec.write_u32!(writer, digest.service)
    Codec.write_hash!(writer, digest.code_hash)
    Codec.write_hash!(writer, digest.payload_hash)
    Codec.write_u64!(writer, digest.gas_accumulate)

    # Work result
    result_encoded = encode_work_result(digest.result)
    copyto!(writer.buffer, writer.pos, result_encoded, 1, length(result_encoded))
    writer.pos += length(result_encoded)

    # Natural numbers
    Codec.write_natural!(writer, digest.gas_used)
    Codec.write_natural!(writer, digest.imports_count)
    Codec.write_natural!(writer, digest.exports_count)
    Codec.write_natural!(writer, digest.extrinsics_count)
    Codec.write_natural!(writer, digest.extrinsics_size)

    return Codec.finalize_writer(writer)
end

# ===== Block Structures =====

# Header encoding unsigned
function encode_header_unsigned(header)
    size = size_of_header_unsigned(header)
    writer = Codec.Writer(size)

    Codec.write_hash!(writer, header.parent_hash)
    Codec.write_hash!(writer, header.state_root)
    Codec.write_hash!(writer, header.extrinsic_hash)
    Codec.write_u32!(writer, header.timeslot)

    # Optional fields - using old method
    epoch_encoded = ComplexCodec.encode_option(header.epoch_marker)
    copyto!(writer.buffer, writer.pos, epoch_encoded, 1, length(epoch_encoded))
    writer.pos += length(epoch_encoded)

    tickets_encoded = ComplexCodec.encode_option(header.winning_tickets)
    copyto!(writer.buffer, writer.pos, tickets_encoded, 1, length(tickets_encoded))
    writer.pos += length(tickets_encoded)

    Codec.write_u16!(writer, header.author_index)
    Codec.write_hash!(writer, header.vrf_signature)

    # Offenders - using old method
    offenders_encoded = ComplexCodec.encode_with_length(header.offenders)
    copyto!(writer.buffer, writer.pos, offenders_encoded, 1, length(offenders_encoded))
    writer.pos += length(offenders_encoded)

    return Codec.finalize_writer(writer)
end

# Full header encoding with seal
function encode_header(header)
    unsigned = encode_header_unsigned(header)
    seal = encode(header.seal)

    # Single allocation for final result
    result = Vector{UInt8}(undef, length(unsigned) + length(seal))
    copyto!(result, 1, unsigned, 1, length(unsigned))
    copyto!(result, length(unsigned) + 1, seal, 1, length(seal))

    return result
end

end # module JAMCodec
