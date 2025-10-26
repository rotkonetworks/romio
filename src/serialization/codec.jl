# src/serialization/codec.jl
# JAM serialization codec per spec section C
# Optimized zero-copy implementation with single pre-allocated buffer

module Codec

using StaticArrays

export encode, encode_fixed, encode_u8, encode_u16, encode_u32, encode_u64
export Writer, write_u8!, write_u16!, write_u32!, write_u64!, write_natural!
export write_hash!, write_blob!, finalize_writer, size_of_natural

# ===== Writer for zero-copy encoding =====

mutable struct Writer
    buffer::Vector{UInt8}
    pos::Int
end

Writer(size::Int) = Writer(Vector{UInt8}(undef, size), 1)
finalize_writer(w::Writer) = resize!(w.buffer, w.pos - 1)

# ===== Legacy interface (for compatibility) =====

encode(::Nothing) = UInt8[]
encode(data::Vector{UInt8}) = data
encode(data::SVector{N, UInt8}) where N = collect(data)
encode(b::Bool) = [b ? 0x01 : 0x00]
encode(t::Tuple) = vcat(map(encode, t)...)

function encode(x::Integer)
    if x < 0
        error("Cannot encode negative integers as naturals")
    end
    size = size_of_natural(x)
    writer = Writer(size)
    write_natural!(writer, x)
    return finalize_writer(writer)
end

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

encode_u8(x::Integer) = encode_fixed(x, 1)
encode_u16(x::Integer) = encode_fixed(x, 2)
encode_u32(x::Integer) = encode_fixed(x, 4)
encode_u64(x::Integer) = encode_fixed(x, 8)

# ===== Optimized zero-copy write functions =====

@inline function write_u8!(w::Writer, x::UInt8)
    @inbounds w.buffer[w.pos] = x
    w.pos += 1
end

@inline function write_u16!(w::Writer, x::UInt16)
    p = w.pos
    @inbounds begin
        w.buffer[p]     = UInt8(x & 0xff)
        w.buffer[p + 1] = UInt8((x >> 8) & 0xff)
    end
    w.pos = p + 2
end

@inline function write_u32!(w::Writer, x::UInt32)
    p = w.pos
    @inbounds begin
        w.buffer[p]     = UInt8(x & 0xff)
        w.buffer[p + 1] = UInt8((x >> 8) & 0xff)
        w.buffer[p + 2] = UInt8((x >> 16) & 0xff)
        w.buffer[p + 3] = UInt8((x >> 24) & 0xff)
    end
    w.pos = p + 4
end

@inline function write_u64!(w::Writer, x::UInt64)
    p = w.pos
    @inbounds begin
        w.buffer[p]     = UInt8(x & 0xff)
        w.buffer[p + 1] = UInt8((x >> 8) & 0xff)
        w.buffer[p + 2] = UInt8((x >> 16) & 0xff)
        w.buffer[p + 3] = UInt8((x >> 24) & 0xff)
        w.buffer[p + 4] = UInt8((x >> 32) & 0xff)
        w.buffer[p + 5] = UInt8((x >> 40) & 0xff)
        w.buffer[p + 6] = UInt8((x >> 48) & 0xff)
        w.buffer[p + 7] = UInt8((x >> 56) & 0xff)
    end
    w.pos = p + 8
end

@inline function size_of_natural(x::Integer)::Int
    if x == 0 || x < 128
        return 1
    elseif x < 16384
        return 2
    elseif x < 2097152
        return 3
    else
        return 9
    end
end

function write_natural!(w::Writer, x::Integer)
    p = w.pos
    if x == 0
        @inbounds w.buffer[p] = 0x00
        w.pos = p + 1
    elseif x < 128
        @inbounds w.buffer[p] = UInt8(x)
        w.pos = p + 1
    elseif x < 16384
        @inbounds begin
            w.buffer[p]     = UInt8(0x80 | (x >> 8))
            w.buffer[p + 1] = UInt8(x & 0xff)
        end
        w.pos = p + 2
    elseif x < 2097152
        @inbounds begin
            w.buffer[p]     = UInt8(0xc0 | (x >> 16))
            w.buffer[p + 1] = UInt8((x >> 8) & 0xff)
            w.buffer[p + 2] = UInt8(x & 0xff)
        end
        w.pos = p + 3
    else
        @inbounds w.buffer[p] = 0xff
        w.pos = p + 1
        write_u64!(w, UInt64(x))
    end
end

@inline function write_hash!(w::Writer, h::SVector{32, UInt8})
    p = w.pos
    @inbounds for i in 1:32
        w.buffer[p + i - 1] = h[i]
    end
    w.pos = p + 32
end

@inline function write_hash!(w::Writer, h::Vector{UInt8})
    @assert length(h) == 32 "Hash must be 32 bytes"
    p = w.pos
    unsafe_copyto!(w.buffer, p, h, 1, 32)
    w.pos = p + 32
end

function write_blob!(w::Writer, data::Vector{UInt8})
    write_natural!(w, length(data))
    if !isempty(data)
        p = w.pos
        copyto!(w.buffer, p, data, 1, length(data))
        w.pos = p + length(data)
    end
end

end # module Codec
