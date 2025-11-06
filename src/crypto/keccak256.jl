# Keccak-256 implementation for Ethereum-compatible hashing
# Based on KangarooTwelve.jl (https://github.com/tecosaur/KangarooTwelve.jl)
# License: MIT (same as KangarooTwelve.jl)

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

# Keccak-256 hash function (Ethereum-compatible)
# Uses 0x01 delim suffix (original Keccak) vs 0x06 (SHA3)
function keccak_256(data::Vector{UInt8})::Vector{UInt8}
    # Keccak-256 parameters: rate = 1088 bits = 136 bytes
    rate_bytes = 136

    # Initialize state to all zeros
    state = EMPTY_STATE

    # Absorb phase - process data in rate-sized blocks
    pos = 1
    while pos + rate_bytes <= length(data) + 1
        # XOR current block into state (little-endian, 8 bytes at a time)
        for lane in 1:17  # rate_bytes / 8 = 17 lanes
            byte_pos = pos + (lane - 1) * 8
            if byte_pos + 7 <= length(data)
                # Read 8 bytes as little-endian UInt64
                val = zero(UInt64)
                for j in 0:7
                    val |= UInt64(data[byte_pos + j]) << (8 * j)
                end
                state = Base.setindex(state, state[lane] ⊻ val, lane)
            end
        end
        state = keccak_p1600(state)
        pos += rate_bytes
    end

    # Absorb remaining bytes
    remaining = length(data) - pos + 1
    for i in 0:remaining-1
        lane = i ÷ 8 + 1
        byte_in_lane = i % 8
        state = Base.setindex(state,
            state[lane] ⊻ (UInt64(data[pos + i]) << (8 * byte_in_lane)),
            lane)
    end

    # Padding: original Keccak uses 0x01 || 0^* || 0x80
    # Apply 0x01 suffix at position after last data byte
    pad_lane = remaining ÷ 8 + 1
    pad_byte = remaining % 8
    state = Base.setindex(state,
        state[pad_lane] ⊻ (UInt64(0x01) << (8 * pad_byte)),
        pad_lane)

    # Apply 0x80 at last byte of rate (byte 135, lane 17, byte 7)
    state = Base.setindex(state,
        state[17] ⊻ (UInt64(0x80) << 56),
        17)

    # Final permutation
    state = keccak_p1600(state)

    # Squeeze phase - extract 32 bytes (256 bits) in little-endian
    output = zeros(UInt8, 32)
    for lane in 1:4  # First 4 lanes = 32 bytes
        for j in 0:7
            output[(lane-1)*8 + j + 1] = UInt8((state[lane] >> (8 * j)) & 0xff)
        end
    end

    return output
end

export keccak_256
