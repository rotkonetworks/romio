# Merkle Mountain Range (MMR) operations - Optimized
# Per graypaper section on MMR (merklization.tex lines 266-316)

include("../crypto/keccak256.jl")
include("../types/basic.jl")

# Thread-local buffers for hash concatenation (avoid allocations)
const MMR_MERGE_BUFFERS = [Vector{UInt8}(undef, 64) for _ in 1:Threads.nthreads()]
const PEAK_PREFIX = SVector{5, UInt8}([0x24, 0x70, 0x65, 0x61, 0x6b])  # "$peak"

# Optimized struct: use Hash instead of Union{Nothing, Vector{UInt8}}
struct MMR
    peaks::Vector{Hash}
    count::Int  # Number of valid (non-zero) peaks
end

# Constructor from nothing-based peaks (for compatibility)
function MMR(old_peaks::Vector{Union{Nothing, Vector{UInt8}}})
    new_peaks = Vector{Hash}(undef, length(old_peaks))
    count = 0

    @inbounds for i in eachindex(old_peaks)
        if old_peaks[i] === nothing
            new_peaks[i] = H0
        else
            new_peaks[i] = Hash(old_peaks[i])
            count += 1
        end
    end

    return MMR(new_peaks, count)
end

# Merge two peaks with keccak using thread-local buffer
@inline function merge_peaks(left::Hash, right::Hash)::Hash
    tid = Threads.threadid()
    buffer = MMR_MERGE_BUFFERS[tid]

    @inbounds begin
        copyto!(buffer, 1, left, 1, 32)
        copyto!(buffer, 33, right, 1, 32)
    end

    return Hash(keccak_256(buffer))
end

# MMR append function - iterative instead of recursive
# Per graypaper equation 277-295
function mmr_append(
    mmr::MMR,
    leaf::Hash
)::MMR
    # Make a copy of peaks for modification
    peaks = copy(mmr.peaks)
    count = mmr.count

    n = 0
    current = leaf

    # Iteratively merge with existing peaks
    @inbounds while n < length(peaks) && peaks[n + 1] != H0
        # Merge current with peak at position n
        current = merge_peaks(peaks[n + 1], current)
        peaks[n + 1] = H0  # Clear the merged peak
        count -= 1
        n += 1
    end

    # Place the final merged result
    if n >= length(peaks)
        # Need to grow the peaks array
        push!(peaks, current)
    else
        peaks[n + 1] = current
    end
    count += 1

    return MMR(peaks, count)
end

# Compatibility wrapper for old signature
function mmr_append(
    peaks::Vector{Union{Nothing, Vector{UInt8}}},
    leaf::Vector{UInt8},
    hash_func::Function = keccak_256
)::Vector{Union{Nothing, Vector{UInt8}}}
    # Convert to new format
    mmr = MMR(peaks)
    leaf_hash = Hash(leaf)

    # Append
    new_mmr = mmr_append(mmr, leaf_hash)

    # Convert back to old format
    result = Vector{Union{Nothing, Vector{UInt8}}}(undef, length(new_mmr.peaks))
    @inbounds for i in eachindex(new_mmr.peaks)
        if new_mmr.peaks[i] == H0
            result[i] = nothing
        else
            result[i] = Vector{UInt8}(new_mmr.peaks[i])
        end
    end

    return result
end

# MMR super peak function - iterative instead of recursive
# Per graypaper equation 307-316
function mmr_super_peak(mmr::MMR)::Hash
    # Filter valid (non-zero) peaks
    valid_peaks = Hash[]
    sizehint!(valid_peaks, mmr.count)

    @inbounds for i in 1:length(mmr.peaks)
        if mmr.peaks[i] != H0
            push!(valid_peaks, mmr.peaks[i])
        end
    end

    if length(valid_peaks) == 0
        return H0
    elseif length(valid_peaks) == 1
        return valid_peaks[1]
    end

    # Iterative approach with buffer reuse
    tid = Threads.threadid()
    buffer = Vector{UInt8}(undef, 69)  # 5 + 32 + 32
    @inbounds copyto!(buffer, 1, PEAK_PREFIX, 1, 5)

    result = valid_peaks[1]

    @inbounds for i in 2:length(valid_peaks)
        copyto!(buffer, 6, result, 1, 32)
        copyto!(buffer, 38, valid_peaks[i], 1, 32)
        result = Hash(keccak_256(buffer))
    end

    return result
end

# Compatibility wrapper for old signature
function mmr_super_peak(peaks::Vector{Union{Nothing, Vector{UInt8}}})::Vector{UInt8}
    mmr = MMR(peaks)
    result = mmr_super_peak(mmr)
    return Vector{UInt8}(result)
end

# Export functions
export mmr_append, mmr_super_peak, keccak_256, MMR
