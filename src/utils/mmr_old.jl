# Merkle Mountain Range (MMR) operations
# Per graypaper section on MMR (merklization.tex lines 266-316)

include("../crypto/keccak256.jl")

# MMR append function per graypaper equation 277-295
# Appends a new leaf to the MMR, performing binary tree merging
function mmr_append(
    peaks::Vector{Union{Nothing, Vector{UInt8}}},
    leaf::Vector{UInt8},
    hash_func::Function = keccak_256
)::Vector{Union{Nothing, Vector{UInt8}}}
    # Recursive helper P(r, l, n, H)
    function P(r, l, n)
        if n >= length(r)
            # Append new peak
            return vcat(r, [l])
        elseif r[n+1] === nothing  # Julia 1-indexed
            # Empty slot - place leaf here
            result = copy(r)
            result[n+1] = l
            return result
        else
            # Peak exists - merge and recurse
            merged = hash_func(vcat(r[n+1], l))
            result = copy(r)
            result[n+1] = nothing
            return P(result, merged, n + 1)
        end
    end

    return P(peaks, leaf, 0)
end

# MMR super peak function per graypaper equation 307-316
# Computes a single hash commitment from all MMR peaks
function mmr_super_peak(peaks::Vector{Union{Nothing, Vector{UInt8}}})::Vector{UInt8}
    # Filter out nothing values
    h = [p for p in peaks if p !== nothing]

    if length(h) == 0
        # Zero hash
        return zeros(UInt8, 32)
    elseif length(h) == 1
        # Single peak - return it directly
        return h[1]
    else
        # Multiple peaks - recursively hash with "$peak" prefix
        # Per graypaper: keccak("$peak" || mmr_super_peak(h[0..n-2]) || h[n-1])
        function recursive_super_peak(peaks_h)
            if length(peaks_h) == 1
                return peaks_h[1]
            else
                prefix = UInt8[0x24, 0x70, 0x65, 0x61, 0x6b]  # "$peak"
                left = recursive_super_peak(peaks_h[1:end-1])
                right = peaks_h[end]
                return keccak_256(vcat(prefix, left, right))
            end
        end
        return recursive_super_peak(h)
    end
end

# Re-export keccak_256 from crypto module
# (Already loaded via include above)

# Export functions
export mmr_append, mmr_super_peak, keccak_256
