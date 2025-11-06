# Keccak-256 implementation - Optimized for AMD Ryzen 9 7950X3D
# Based on KangarooTwelve.jl (https://github.com/tecosaur/KangarooTwelve.jl)
# License: MIT (same as KangarooTwelve.jl)

include("../types/basic.jl")

const EMPTY_STATE = ntuple(_ -> zero(UInt64), 25)

const ROUND_CONSTS_24 =
    (0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
     0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
     0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
     0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
     0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
     0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)

const ρs = UInt64.(
    (0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25,
     8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2))

const πs =
    (1, 7, 13, 19, 25, 4, 10, 11, 17, 23, 2, 8, 14,
     20, 21, 5, 6, 12, 18, 24, 3, 9, 15, 16, 22)

const χs =
    (( 2,  3), ( 3,  4), ( 4,  5), ( 5,  1), ( 1,  2), ( 7,  8),
     ( 8,  9), ( 9, 10), (10,  6), ( 6,  7), (12, 13), (13, 14),
     (14, 15), (15, 11), (11, 12), (17, 18), (18, 19), (19, 20),
     (20, 16), (16, 17), (22, 23), (23, 24), (24, 25), (25, 21),
     (21, 22))

# Thread-local output buffers to avoid allocations
const KECCAK_OUTPUT_BUFFERS = [Vector{UInt8}(undef, 32) for _ in 1:Threads.nthreads()]

# Keccak-p[1600, 24] permutation
@inline function keccak_p1600(state::NTuple{25, UInt64})
    @inbounds for round in 1:24
        # θ (diffusion)
        C = ntuple(i -> xor(state[i], state[i+5], state[i+10], state[i+15], state[i+20]), 5)
        D = ntuple(i -> C[mod1(i+4, 5)] ⊻ bitrotate(C[mod1(i+1, 5)], 1), 5)
        state = ntuple(i -> state[i] ⊻ D[mod1(i, 5)], 25)
        # ρ (rotation) and π (lane permutation)
        state = ntuple(i -> bitrotate(state[πs[i]], ρs[i]), 25)
        # χ (intra-row bitwise combination, nonlinear)
        state = ntuple(i -> state[i] ⊻ (~state[χs[i][1]] & state[χs[i][2]]), 25)
        # ι (symmetry disruptor)
        state = Base.setindex(state, state[1] ⊻ ROUND_CONSTS_24[round], 1)
    end
    state
end

# Fast UInt64 load from byte array (little-endian)
@inline function load_u64_le(data::Vector{UInt8}, pos::Int)
    # Directly load 8 bytes as UInt64 (assumes little-endian system)
    return unsafe_load(Ptr{UInt64}(pointer(data, pos)))
end

# Fast UInt64 store to byte array (little-endian)
@inline function store_u64_le!(output::Vector{UInt8}, pos::Int, val::UInt64)
    unsafe_store!(Ptr{UInt64}(pointer(output, pos)), val)
    return nothing
end

# In-place version: write output to pre-allocated buffer
function keccak_256!(output::Vector{UInt8}, data::Vector{UInt8})
    @assert length(output) == 32 "Output buffer must be 32 bytes"

    # Keccak-256 parameters: rate = 1088 bits = 136 bytes
    rate_bytes = 136

    # Initialize state to all zeros
    state = EMPTY_STATE

    # Absorb phase - optimized with direct UInt64 loads
    pos = 1
    data_len = length(data)

    # Process full rate-sized blocks
    @inbounds while pos + rate_bytes - 1 <= data_len
        # XOR 17 lanes (136 bytes / 8 = 17 UInt64s) into state
        # Using direct memory loads for massive speedup
        for lane in 1:17
            byte_pos = pos + (lane - 1) * 8
            val = load_u64_le(data, byte_pos)
            state = Base.setindex(state, state[lane] ⊻ val, lane)
        end
        state = keccak_p1600(state)
        pos += rate_bytes
    end

    # Absorb remaining bytes (less than one full block)
    remaining = data_len - pos + 1

    @inbounds if remaining > 0
        # Process complete lanes
        num_complete_lanes = remaining >>> 3  # div by 8
        for lane in 1:num_complete_lanes
            byte_pos = pos + (lane - 1) * 8
            val = load_u64_le(data, byte_pos)
            state = Base.setindex(state, state[lane] ⊻ val, lane)
        end

        # Process remaining bytes in partial lane
        bytes_processed = num_complete_lanes << 3  # * 8
        if bytes_processed < remaining
            lane = num_complete_lanes + 1
            partial_val = zero(UInt64)
            for j in 0:(remaining - bytes_processed - 1)
                partial_val |= UInt64(data[pos + bytes_processed + j]) << (8 * j)
            end
            state = Base.setindex(state, state[lane] ⊻ partial_val, lane)
        end
    end

    # Padding: original Keccak uses 0x01 || 0^* || 0x80
    pad_lane = (remaining >>> 3) + 1
    pad_byte = remaining & 7  # mod 8
    @inbounds state = Base.setindex(state,
        state[pad_lane] ⊻ (UInt64(0x01) << (pad_byte << 3)),  # * 8
        pad_lane)

    # Apply 0x80 at last byte of rate (byte 135, lane 17, byte 7)
    @inbounds state = Base.setindex(state,
        state[17] ⊻ (UInt64(0x80) << 56),
        17)

    # Final permutation
    state = keccak_p1600(state)

    # Squeeze phase - optimized with direct UInt64 stores
    @inbounds for lane in 1:4  # First 4 lanes = 32 bytes
        store_u64_le!(output, (lane-1)*8 + 1, state[lane])
    end

    return nothing
end

# Allocation-free version using thread-local buffer
function keccak_256_fast(data::Vector{UInt8})::Hash
    tid = Threads.threadid()
    output = KECCAK_OUTPUT_BUFFERS[tid]
    keccak_256!(output, data)
    return Hash(output)
end

# Standard allocating version for compatibility
function keccak_256(data::Vector{UInt8})::Vector{UInt8}
    output = Vector{UInt8}(undef, 32)
    keccak_256!(output, data)
    return output
end

# Optimized version for AbstractVector (views, etc)
function keccak_256(data::AbstractVector{UInt8})::Vector{UInt8}
    # Convert to Vector if needed for performance
    if data isa Vector{UInt8}
        return keccak_256(data)
    else
        # Copy to contiguous array for fast pointer access
        data_copy = Vector{UInt8}(data)
        return keccak_256(data_copy)
    end
end

export keccak_256, keccak_256!, keccak_256_fast
