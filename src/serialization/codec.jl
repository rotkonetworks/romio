# src/serialization/codec.jl
# JAM serialization codec per spec section C

module Codec

using StaticArrays

# ===== Basic Types =====

# C.1: Encode nothing/null as empty sequence
encode(::Nothing) = UInt8[]

# C.2: Encode octet sequence as identity
encode(data::Vector{UInt8}) = data
encode(data::SVector{N, UInt8}) where N = collect(data)

# Encode boolean
encode(b::Bool) = [b ? 0x01 : 0x00]

# C.3: Anonymous tuples concatenate their elements
encode(t::Tuple) = vcat(map(encode, t)...)

# C.5: Natural number encoding up to 2^64
function encode(x::Integer)
    if x < 0
        error("Cannot encode negative integers as naturals")
    elseif x == 0
        return [0x00]
    elseif x < 128
        return [UInt8(x)]
    elseif x < 16384
        # 2-byte encoding: [0x80 + high bits, low byte]
        return [UInt8(0x80 | (x >> 8)), UInt8(x & 0xff)]
    elseif x < 2097152  # 2^21
        # 3-byte encoding
        return [UInt8(0xc0 | (x >> 16)), UInt8((x >> 8) & 0xff), UInt8(x & 0xff)]
    else
        # full encoding with 0xff prefix
        return [0xff, encode_fixed(x, 8)...]
    end
end

# C.12: Fixed-length integer encoding (little-endian)
function encode_fixed(x::Integer, l::Int)
    if x < 0
        error("Use encode_signed for negative integers")
    end
    result = zeros(UInt8, l)
    for i in 1:l
        result[i] = UInt8((x >> (8*(i-1))) & 0xff)
    end
    return result
end

# Convenience functions for common sizes
encode_u8(x::Integer) = encode_fixed(x, 1)
encode_u16(x::Integer) = encode_fixed(x, 2)
encode_u32(x::Integer) = encode_fixed(x, 4)
encode_u64(x::Integer) = encode_fixed(x, 8)

export encode, encode_fixed, encode_u8, encode_u16, encode_u32, encode_u64

end # module Codec
