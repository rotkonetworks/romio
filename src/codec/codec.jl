# src/codec/codec.jl
# Complete JAM serialization codec implementation

module Codec

using StaticArrays

# ===== Basic Types =====

# Encode nothing/null
encode(::Nothing) = UInt8[]

# Encode raw bytes (identity)
encode(data::Vector{UInt8}) = data
encode(data::SVector{N, UInt8}) where N = collect(data)

# Encode boolean
encode(b::Bool) = [b ? 0x01 : 0x00]

# ===== Natural Numbers (Variable Length) =====
# Per spec equation C.5
function encode(x::Integer)
    if x < 0
        error("Cannot encode negative integers as naturals")
    elseif x == 0
        return [0x00]
    elseif x < 2^7
        # single byte for small values
        return [UInt8(x)]
    else
        # find length needed
        l = 1
        while l < 8 && x >= 2^(7*l)
            l += 1
        end
        
        if l == 8 && x >= 2^56
            # use full 8-byte encoding with 0xff prefix
            return [0xff, encode_fixed(x, 8)...]
        else
            # variable length with prefix byte
            prefix = UInt8(2^8 - 2^(8-l) + (x ÷ 2^(8*l)))
            remainder = encode_fixed(x % 2^(8*l), l)
            return [prefix, remainder...]
        end
    end
end

# ===== Fixed-Length Integer Encoding (Little Endian) =====
# Per spec equation C.12
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
