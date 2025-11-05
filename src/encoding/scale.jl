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
