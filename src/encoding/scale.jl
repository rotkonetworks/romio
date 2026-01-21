# SCALE (Simple Concatenated Aggregate Little-Endian) encoding
# Used by JAM protocol for serializing data structures

"""
Encode length as SCALE compact integer.
- Single-byte mode (0-63): [xx......] where xx = 00
- Two-byte mode (64-16383): [xx......] [........] where xx = 01
- Four-byte mode (16384-2^30-1): [xx......] [...] [...] [...] where xx = 10
- Big-integer mode (2^30+): [00000011] [len in 4 bytes] [data]
"""
function encode_compact_length(n::Integer)::Vector{UInt8}
    if n < 64
        # Single-byte mode
        return [UInt8(n << 2)]
    elseif n < 2^14
        # Two-byte mode
        return [UInt8(((n & 0x3f) << 2) | 1), UInt8((n >> 6) & 0xff)]
    elseif n < 2^30
        # Four-byte mode
        return [
            UInt8(((n & 0x3f) << 2) | 2),
            UInt8((n >> 6) & 0xff),
            UInt8((n >> 14) & 0xff),
            UInt8((n >> 22) & 0xff)
        ]
    else
        # Big-integer mode (length > 2^30)
        return vcat([UInt8(3)], reinterpret(UInt8, [UInt32(n)]))
    end
end

"""
Encode a blob (variable-length byte array) with SCALE compact length prefix.
"""
function encode_blob(data::Vector{UInt8})::Vector{UInt8}
    return vcat(encode_compact_length(length(data)), data)
end

"""
Encode an optional value. None is encoded as 0x00, Some(value) as 0x01 followed by the encoded value.
"""
function encode_optional(value::Union{Nothing, Vector{UInt8}})::Vector{UInt8}
    if value === nothing
        return [UInt8(0)]
    else
        return vcat([UInt8(1)], value)
    end
end

"""
Encode UInt64 as fixed-width 8-byte little-endian.
"""
function encode_u64(x::UInt64)::Vector{UInt8}
    return [UInt8(x & 0xff), UInt8((x >> 8) & 0xff),
            UInt8((x >> 16) & 0xff), UInt8((x >> 24) & 0xff),
            UInt8((x >> 32) & 0xff), UInt8((x >> 40) & 0xff),
            UInt8((x >> 48) & 0xff), UInt8((x >> 56) & 0xff)]
end

"""
Encode UInt32 as fixed-width 4-byte little-endian.
"""
function encode_u32(x::UInt32)::Vector{UInt8}
    return [UInt8(x & 0xff), UInt8((x >> 8) & 0xff),
            UInt8((x >> 16) & 0xff), UInt8((x >> 24) & 0xff)]
end

"""
Encode a JAM ServiceAccount to 89-byte SCALE format.
Format: code_hash(32) + balance(9: 0xef + 8 bytes) + min_acc_gas(8) + min_memo_gas(8)
        + storage_octets(8) + storage_items(8) + preimage_octets(8) + preimage_items(8)
"""
function encode_service_account(;
    code_hash::Vector{UInt8},
    balance::UInt64,
    min_acc_gas::UInt64 = UInt64(10),
    min_memo_gas::UInt64 = UInt64(10),
    storage_octets::UInt64,
    storage_items::UInt64,
    preimage_octets::UInt64,
    preimage_items::UInt64
)::Vector{UInt8}
    data = UInt8[]

    # code_hash (32 bytes) - first byte is version 0x00, then 31 bytes of hash
    push!(data, 0x00)  # version byte
    if isempty(code_hash)
        append!(data, zeros(UInt8, 31))
    else
        append!(data, code_hash[1:min(31, length(code_hash))])
        if length(code_hash) < 31
            append!(data, zeros(UInt8, 31 - length(code_hash)))
        end
    end

    # balance (9 bytes: 0xef prefix + 8 bytes LE)
    push!(data, 0xef)
    append!(data, encode_u64(balance))

    # min_acc_gas (8 bytes LE)
    append!(data, encode_u64(min_acc_gas))

    # min_memo_gas (8 bytes LE)
    append!(data, encode_u64(min_memo_gas))

    # storage_octets (8 bytes LE)
    append!(data, encode_u64(storage_octets))

    # storage_items (8 bytes LE)
    append!(data, encode_u64(storage_items))

    # preimage_octets (8 bytes LE)
    append!(data, encode_u64(preimage_octets))

    # preimage_items (8 bytes LE)
    append!(data, encode_u64(preimage_items))

    return data
end
