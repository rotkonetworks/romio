# src/codec/complex.jl
# Complex type encoding for JAM structures

module ComplexCodec

using ..Codec
using StaticArrays

# ===== Size Calculation Functions =====

function size_of_item_lengths_sequence(seq::Vector{Vector{UInt8}})::Int
    size = Codec.size_of_natural(length(seq))
    for item in seq
        size += Codec.size_of_natural(length(item))
        size += length(item)
    end
    return size
end

# ===== Tuples =====
# Anonymous tuples concatenate their elements
function encode(t::Tuple)
    result = UInt8[]
    sizehint!(result, 32 * length(t))  # Reduce reallocations
    for elem in t
        append!(result, Codec.encode(elem))
    end
    return result
end

# Named tuples same as anonymous
encode(t::NamedTuple) = encode(values(t))

# ===== Sequences/Arrays =====

# Fixed-length sequences - just concatenate
function encode(seq::Vector{T}) where T
    result = UInt8[]
    sizehint!(result, 32 * length(seq))  # Reduce reallocations
    for item in seq
        append!(result, Codec.encode(item))
    end
    return result
end

# Variable-length sequences with discriminator
function encode_with_length(seq::Vector{T}) where T
    result = Codec.encode(length(seq))  # length prefix
    sizehint!(result, 32 * length(seq))  # Reduce reallocations
    for item in seq
        append!(result, Codec.encode(item))
    end
    return result
end

# For sequences of variable-length items (double discriminator)
function encode_with_item_lengths(seq::Vector{Vector{UInt8}})
    size = size_of_item_lengths_sequence(seq)
    writer = Codec.Writer(size)

    Codec.write_natural!(writer, length(seq))
    for item in seq
        Codec.write_blob!(writer, item)
    end

    return Codec.finalize_writer(writer)
end

# ===== Bit Sequences =====
# Pack bits into bytes, LSB first
function encode(bits::BitVector)
    n = length(bits)
    bytes = zeros(UInt8, (n + 7) ÷ 8)

    @inbounds for i in 1:n
        if bits[i]
            byte_idx = (i-1) ÷ 8 + 1
            bit_idx = (i-1) % 8
            bytes[byte_idx] |= (1 << bit_idx)
        end
    end

    return bytes
end

function encode_with_length(bits::BitVector)
    return [Codec.encode(length(bits)); encode(bits)]
end

# ===== Dictionaries =====
# Encode as sorted sequence of pairs
function encode(dict::Dict{K,V}) where {K,V}
    pairs = [(k, v) for (k, v) in dict]
    sort!(pairs, by=first)

    result = Codec.encode(length(pairs))
    sizehint!(result, 64 * length(pairs))  # Reduce reallocations
    for (k, v) in pairs
        append!(result, Codec.encode(k))
        append!(result, Codec.encode(v))
    end
    return result
end

# ===== Optional/Union Types =====

# Option discriminator (0 for nothing, 1 + value for something)
function encode_option(value::Union{Nothing, T}) where T
    if value === nothing
        return [0x00]
    else
        return [0x01, Codec.encode(value)...]
    end
end

# Union types with discriminator
function encode_union(value, types::Vector{DataType})
    for (i, T) in enumerate(types)
        if isa(value, T)
            return [UInt8(i-1), Codec.encode(value)...]
        end
    end
    error("Value type not in union types")
end

export encode, encode_with_length, encode_with_item_lengths
export encode_option, encode_union

end # module ComplexCodec
