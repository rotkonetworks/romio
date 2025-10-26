# Decoding functions for JAM serialization
# Optimized with zero-copy views where possible

module Decoder

using StaticArrays

export decode_natural, decode_fixed_u64, decode_fixed_u32, decode_fixed_u16, decode_fixed_u8
export decode_hash, decode_with_length, decode_blob, decode_option, decode_bits
export trailing_ones
export Reader, read_u8, read_u16, read_u32, read_u64, read_natural
export read_hash, read_hash_view, read_blob, read_blob_view

# ===== Reader for zero-copy decoding =====

mutable struct Reader
    data::Vector{UInt8}
    pos::Int
end

Reader(data::Vector{UInt8}) = Reader(data, 1)

@inline function check_bounds(r::Reader, n::Int)
    if r.pos + n - 1 > length(r.data)
        error("Unexpected end of data: need $n bytes, have $(length(r.data) - r.pos + 1)")
    end
end

@inline function read_u8(r::Reader)::UInt8
    check_bounds(r, 1)
    @inbounds val = r.data[r.pos]
    r.pos += 1
    return val
end

@inline function read_u16(r::Reader)::UInt16
    check_bounds(r, 2)
    p = r.pos
    @inbounds val = UInt16(r.data[p]) | (UInt16(r.data[p + 1]) << 8)
    r.pos = p + 2
    return val
end

@inline function read_u32(r::Reader)::UInt32
    check_bounds(r, 4)
    p = r.pos
    @inbounds val = (
        UInt32(r.data[p]) |
        (UInt32(r.data[p + 1]) << 8) |
        (UInt32(r.data[p + 2]) << 16) |
        (UInt32(r.data[p + 3]) << 24)
    )
    r.pos = p + 4
    return val
end

@inline function read_u64(r::Reader)::UInt64
    check_bounds(r, 8)
    p = r.pos
    @inbounds val = (
        UInt64(r.data[p]) |
        (UInt64(r.data[p + 1]) << 8) |
        (UInt64(r.data[p + 2]) << 16) |
        (UInt64(r.data[p + 3]) << 24) |
        (UInt64(r.data[p + 4]) << 32) |
        (UInt64(r.data[p + 5]) << 40) |
        (UInt64(r.data[p + 6]) << 48) |
        (UInt64(r.data[p + 7]) << 56)
    )
    r.pos = p + 8
    return val
end

function read_natural(r::Reader)::UInt64
    check_bounds(r, 1)
    p = r.pos
    @inbounds first = r.data[p]

    if first == 0x00
        r.pos = p + 1
        return UInt64(0)
    elseif first < 0x80
        r.pos = p + 1
        return UInt64(first)
    elseif first < 0xc0
        check_bounds(r, 2)
        @inbounds val = ((UInt64(first) & 0x3f) << 8) | UInt64(r.data[p + 1])
        r.pos = p + 2
        return val
    elseif first < 0xe0
        check_bounds(r, 3)
        @inbounds val = (
            ((UInt64(first) & 0x1f) << 16) |
            (UInt64(r.data[p + 1]) << 8) |
            UInt64(r.data[p + 2])
        )
        r.pos = p + 3
        return val
    elseif first == 0xff
        r.pos = p + 1
        return read_u64(r)
    else
        error("Invalid natural encoding: first byte = 0x$(string(first, base=16))")
    end
end

function read_hash(r::Reader)::SVector{32, UInt8}
    check_bounds(r, 32)
    p = r.pos
    @inbounds hash = SVector{32, UInt8}(r.data[p:p+31])
    r.pos = p + 32
    return hash
end

function read_hash_view(r::Reader)::SubArray{UInt8, 1}
    check_bounds(r, 32)
    p = r.pos
    view = @view r.data[p:p+31]
    r.pos = p + 32
    return view
end

function read_blob(r::Reader)::Vector{UInt8}
    len = Int(read_natural(r))
    check_bounds(r, len)
    p = r.pos
    blob = r.data[p:p+len-1]
    r.pos = p + len
    return blob
end

function read_blob_view(r::Reader)::SubArray{UInt8, 1}
    len = Int(read_natural(r))
    if len == 0
        return @view r.data[1:0]
    end
    check_bounds(r, len)
    p = r.pos
    view = @view r.data[p:p+len-1]
    r.pos = p + len
    return view
end

# ===== Legacy interface (for compatibility) =====

function decode_natural(data::Vector{UInt8}, offset::Int=1)
    if offset > length(data)
        error("Offset out of bounds")
    end

    first = data[offset]
    if first == 0x00
        return (0, offset + 1)
    elseif first < 0x80
        return (Int(first), offset + 1)
    elseif first < 0xc0
        val = ((Int(first) & 0x3f) << 8) | Int(data[offset + 1])
        return (val, offset + 2)
    elseif first < 0xe0
        val = ((Int(first) & 0x1f) << 16) | (Int(data[offset + 1]) << 8) | Int(data[offset + 2])
        return (val, offset + 3)
    elseif first == 0xff
        value = decode_fixed_u64(data, offset + 1)
        return (value, offset + 9)
    else
        error("Unsupported encoding prefix: $(first)")
    end
end

function trailing_ones(b::UInt8)
    count = 0
    mask = 0x80
    while (b & mask) != 0 && count < 8
        count += 1
        mask >>= 1
    end
    return count
end

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

function decode_hash(data::Vector{UInt8}, offset::Int)
    if offset + 31 > length(data)
        error("Not enough data for hash")
    end
    return SVector{32, UInt8}(data[offset:offset+31])
end

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

function decode_blob(data::Vector{UInt8}, offset::Int)
    len, new_offset = decode_natural(data, offset)
    if new_offset + len - 1 > length(data)
        error("Not enough data for blob")
    end
    blob = data[new_offset:new_offset+len-1]
    return (blob, new_offset + len)
end

function decode_option(data::Vector{UInt8}, offset::Int, decoder::Function)
    if data[offset] == 0x00
        return (nothing, offset + 1)
    else
        value, new_offset = decoder(data, offset + 1)
        return (value, new_offset)
    end
end

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

end # module Decoder
