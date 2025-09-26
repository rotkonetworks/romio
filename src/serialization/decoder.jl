# src/codec/decoder.jl
# Decoding functions for JAM serialization

module Decoder

using StaticArrays

# ===== Basic Decoding =====

# Decode variable-length natural
function decode_natural(data::Vector{UInt8}, offset::Int=1)
    if offset > length(data)
        error("Offset out of bounds")
    end
    
    first = data[offset]
    if first == 0x00
        return (0, offset + 1)
    elseif first < 128
        return (Int(first), offset + 1)
    elseif first == 0xff
        # 8-byte encoding
        value = decode_fixed_u64(data, offset + 1)
        return (value, offset + 9)
    else
        # variable length
        l = trailing_ones(first) + 1
        prefix_val = first & ((1 << (8-l)) - 1)
        
        value = prefix_val
        for i in 1:l
            value = (value << 8) | data[offset + i]
        end
        return (value, offset + l + 1)
    end
end

# Count trailing ones in a byte
function trailing_ones(b::UInt8)
    count = 0
    mask = 0x80
    while (b & mask) != 0 && count < 8
        count += 1
        mask >>= 1
    end
    return count
end

# Decode fixed-length integers (little-endian)
function decode_fixed_u64(data::Vector{UInt8}, offset::Int)
    value = UInt64(0)
    for i in 0:7
        value |= UInt64(data[offset + i]) << (8*i)
    end
    return value
end

function decode_fixed_u32(data::Vector{UInt8}, offset::Int)
    value = UInt32(0)
    for i in 0:3
        value |= UInt32(data[offset + i]) << (8*i)
    end
    return value
end

function decode_fixed_u16(data::Vector{UInt8}, offset::Int)
    return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
end

function decode_fixed_u8(data::Vector{UInt8}, offset::Int)
    return data[offset]
end

# Decode hash (32 bytes)
function decode_hash(data::Vector{UInt8}, offset::Int)
    if offset + 31 > length(data)
        error("Not enough data for hash")
    end
    return SVector{32, UInt8}(data[offset:offset+31])
end

# Decode with length prefix
function decode_with_length(data::Vector{UInt8}, offset::Int, decoder::Function)
    len, new_offset = decode_natural(data, offset)
    items = []
    current = new_offset
    
    for i in 1:len
        item, current = decoder(data, current)
        push!(items, item)
    end
    
    return (items, current)
end

# Decode blob with length prefix
function decode_blob(data::Vector{UInt8}, offset::Int)
    len, new_offset = decode_natural(data, offset)
    if new_offset + len - 1 > length(data)
        error("Not enough data for blob")
    end
    blob = data[new_offset:new_offset+len-1]
    return (blob, new_offset + len)
end

# Decode optional value
function decode_option(data::Vector{UInt8}, offset::Int, decoder::Function)
    if data[offset] == 0x00
        return (nothing, offset + 1)
    else
        value, new_offset = decoder(data, offset + 1)
        return (value, new_offset)
    end
end

# Decode bit sequence
function decode_bits(data::Vector{UInt8}, offset::Int, nbits::Int)
    nbytes = (nbits + 7) ÷ 8
    if offset + nbytes - 1 > length(data)
        error("Not enough data for bits")
    end
    
    bits = falses(nbits)
    for i in 1:nbits
        byte_idx = (i-1) ÷ 8
        bit_idx = (i-1) % 8
        bits[i] = (data[offset + byte_idx] >> bit_idx) & 1 == 1
    end
    
    return (bits, offset + nbytes)
end

export decode_natural, decode_fixed_u64, decode_fixed_u32, decode_fixed_u16, decode_fixed_u8
export decode_hash, decode_with_length, decode_blob, decode_option, decode_bits
export trailing_ones

end # module Decoder
