# Keccak-256 implementation - Optimized with mutable state
# Uses MVector for zero-allocation permutation

include("../types/basic.jl")

using StaticArrays

# Round constants for Keccak-p[1600, 24]
const RC = SVector{24, UInt64}(
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)

# Rotation offsets (ρ step)
const RHO = SVector{25, Int}(
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14)

# Pi permutation: where does lane i go? π(x,y) = (y, 2x+3y mod 5)
# i = x + 5*y -> j = y + 5*(2x+3y mod 5)
const PI = SVector{25, Int}(
    1, 11, 21, 6, 16,
    17, 2, 12, 22, 7,
    8, 18, 3, 13, 23,
    24, 9, 19, 4, 14,
    15, 25, 10, 20, 5)

# Thread-local state buffers
const KECCAK_STATES = [MVector{25, UInt64}(zeros(UInt64, 25)) for _ in 1:Threads.nthreads()]
const KECCAK_TEMPS = [MVector{25, UInt64}(zeros(UInt64, 25)) for _ in 1:Threads.nthreads()]
const KECCAK_C = [MVector{5, UInt64}(zeros(UInt64, 5)) for _ in 1:Threads.nthreads()]
const KECCAK_OUTPUT_BUFFERS = [Vector{UInt8}(undef, 32) for _ in 1:Threads.nthreads()]

# Keccak-p[1600, 24] permutation - optimized with mutable arrays
@inline function keccak_p!(state::MVector{25, UInt64}, temp::MVector{25, UInt64}, C::MVector{5, UInt64})
    @inbounds for round in 1:24
        # θ step - column parity
        for x in 1:5
            C[x] = state[x] ⊻ state[x+5] ⊻ state[x+10] ⊻ state[x+15] ⊻ state[x+20]
        end

        for x in 1:5
            # D[x] = C[x-1] ⊻ rot(C[x+1], 1)
            D = C[mod1(x-1, 5)] ⊻ bitrotate(C[mod1(x+1, 5)], 1)
            for y in 0:4
                state[x + 5*y] ⊻= D
            end
        end

        # ρ and π steps combined
        for i in 1:25
            temp[PI[i]] = bitrotate(state[i], RHO[i])
        end

        # χ step - non-linear mixing
        for y in 0:4
            y5 = 5*y
            for x in 1:5
                state[x + y5] = temp[x + y5] ⊻ (~temp[mod1(x+1, 5) + y5] & temp[mod1(x+2, 5) + y5])
            end
        end

        # ι step - round constant
        state[1] ⊻= RC[round]
    end
    return nothing
end

# Fast UInt64 load from byte array (little-endian)
@inline function load_u64_le(data::Vector{UInt8}, pos::Int)
    return unsafe_load(Ptr{UInt64}(pointer(data, pos)))
end

# Fast UInt64 store to byte array (little-endian)
@inline function store_u64_le!(output::Vector{UInt8}, pos::Int, val::UInt64)
    unsafe_store!(Ptr{UInt64}(pointer(output, pos)), val)
    return nothing
end

# In-place Keccak-256 hash
function keccak_256!(output::Vector{UInt8}, data::Vector{UInt8})
    tid = Threads.threadid()
    state = KECCAK_STATES[tid]
    temp = KECCAK_TEMPS[tid]
    C = KECCAK_C[tid]

    # Reset state
    @inbounds for i in 1:25
        state[i] = zero(UInt64)
    end

    # Keccak-256 parameters: rate = 1088 bits = 136 bytes
    rate_bytes = 136
    data_len = length(data)
    pos = 1

    # Absorb phase - process full rate-sized blocks
    @inbounds while pos + rate_bytes - 1 <= data_len
        for lane in 1:17
            state[lane] ⊻= load_u64_le(data, pos + (lane - 1) * 8)
        end
        keccak_p!(state, temp, C)
        pos += rate_bytes
    end

    # Absorb remaining bytes
    remaining = data_len - pos + 1

    @inbounds if remaining > 0
        num_complete_lanes = remaining >>> 3
        for lane in 1:num_complete_lanes
            state[lane] ⊻= load_u64_le(data, pos + (lane - 1) * 8)
        end

        bytes_processed = num_complete_lanes << 3
        if bytes_processed < remaining
            lane = num_complete_lanes + 1
            partial_val = zero(UInt64)
            for j in 0:(remaining - bytes_processed - 1)
                partial_val |= UInt64(data[pos + bytes_processed + j]) << (8 * j)
            end
            state[lane] ⊻= partial_val
        end
    end

    # Padding: Keccak uses 0x01 || 0^* || 0x80
    pad_lane = (remaining >>> 3) + 1
    pad_byte = remaining & 7
    @inbounds state[pad_lane] ⊻= UInt64(0x01) << (pad_byte << 3)
    @inbounds state[17] ⊻= UInt64(0x80) << 56

    # Final permutation
    keccak_p!(state, temp, C)

    # Squeeze phase - extract 32 bytes (4 lanes)
    @inbounds for lane in 1:4
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
    if data isa Vector{UInt8}
        return keccak_256(data)
    else
        data_copy = Vector{UInt8}(data)
        return keccak_256(data_copy)
    end
end

export keccak_256, keccak_256!, keccak_256_fast
