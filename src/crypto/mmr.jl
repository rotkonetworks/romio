# src/crypto/mmr.jl
# merkle mountain range implementation for jam

using SHA
using Keccak

"""
merkle mountain range (mmr) - append-only cryptographic data structure
sequence of peaks, each peak is root of merkle tree containing 2^i items
"""
struct MerkleMountainRange
   peaks::Vector{Union{Nothing, Hash}}
end

# create empty mmr
MerkleMountainRange() = MerkleMountainRange(Vector{Union{Nothing, Hash}}())

"""
append a leaf to the mmr
following gray paper equation for mmr_append
"""
function mmr_append!(mmr::MerkleMountainRange, leaf::Hash, H::Function=keccak256)
   append_recursive!(mmr.peaks, leaf, 1, H)
end

function append_recursive!(peaks::Vector{Union{Nothing, Hash}}, leaf::Hash, idx::Int, H::Function)
   # extend peaks vector if needed
   while length(peaks) < idx
       push!(peaks, nothing)
   end
   
   if idx > length(peaks) || peaks[idx] === nothing
       # empty slot - place the leaf here
       if idx <= length(peaks)
           peaks[idx] = leaf
       else
           push!(peaks, leaf)
       end
       return peaks
   else
       # slot occupied - merge and continue
       hash_input = Vector{UInt8}(undef, 64)
       copyto!(hash_input, 1, peaks[idx], 1, 32)
       copyto!(hash_input, 33, leaf, 1, 32)
       merged = H(hash_input)
       peaks[idx] = nothing
       append_recursive!(peaks, merged, idx + 1, H)
   end
end

"""
encode mmr to bytes for serialization
"""
function mmr_encode(mmr::MerkleMountainRange)::Vector{UInt8}
   # encode as sequence of optional hashes
   # Calculate size: each peak is either 1 byte (none) or 1 + 32 bytes (some + hash)
   num_some = count(p -> p !== nothing, mmr.peaks)
   num_none = length(mmr.peaks) - num_some
   size = num_none + num_some * 33

   result = Vector{UInt8}(undef, size)
   pos = 1

   @inbounds for peak in mmr.peaks
       if peak === nothing
           result[pos] = 0x00  # none marker
           pos += 1
       else
           result[pos] = 0x01  # some marker
           copyto!(result, pos + 1, peak, 1, 32)
           pos += 33
       end
   end

   return result
end

"""
compute mmr super-peak (commitment to entire range)
following gray paper - hashes non-empty peaks recursively
"""
function mmr_superpeak(mmr::MerkleMountainRange)::Hash
   # collect non-empty peaks
   peaks = Hash[p for p in mmr.peaks if p !== nothing]
   
   if isempty(peaks)
       return H0
   elseif length(peaks) == 1
       return peaks[1]
   else
       # recursive hashing from left to right
       result = peaks[1]
       hash_input = Vector{UInt8}(undef, 68)
       peak_prefix = b"peak"
       copyto!(hash_input, 1, peak_prefix, 1, 4)
       for i in 2:length(peaks)
           copyto!(hash_input, 5, result, 1, 32)
           copyto!(hash_input, 37, peaks[i], 1, 32)
           result = Hash(keccak256(hash_input))
       end
       return result
   end
end

"""
get the size (number of items) in the mmr
"""
function mmr_size(mmr::MerkleMountainRange)::Int
   size = 0
   for (i, peak) in enumerate(mmr.peaks)
       if peak !== nothing
           size += 2^(i-1)
       end
   end
   return size
end

"""
generate inclusion proof for item at given index
returns path of hashes needed to verify inclusion
"""
function mmr_proof(mmr::MerkleMountainRange, index::Int)::Vector{Hash}
   # find which peak contains this index
   current_idx = 0
   peak_idx = 0
   peak_size = 0
   
   for (i, peak) in enumerate(mmr.peaks)
       if peak !== nothing
           peak_size = 2^(i-1)
           if current_idx + peak_size > index
               peak_idx = i
               break
           end
           current_idx += peak_size
       end
   end
   
   if peak_idx == 0
       error("Index out of range")
   end
   
   # generate merkle path within the peak
   # this would need the full tree data, simplified here
   return Hash[]  # placeholder - would need full tree storage
end

# keccak-256 helper
function keccak256(data::Vector{UInt8})::Vector{UInt8}
   sponge = Keccak.KeccakSponge{17, UInt64}(Keccak.KeccakPad(0x01))
   sponge = Keccak.absorb(sponge, data)
   sponge = Keccak.pad(sponge)
   result = Keccak.squeeze(sponge, Val(32))[2]
   return collect(result)
end

# ===== merkle mountain belt (mmb) =====
# belt is mmr with additional structure for accumulation outputs

"""
merkle mountain belt - specialized mmr for accumulation outputs
tracks both the mmr structure and accumulation metadata
"""
struct MerkleMountainBelt
   mmr::MerkleMountainRange
   # track accumulation outputs for each peak
   accumulation_outputs::Vector{Vector{Tuple{ServiceId, Hash}}}
end

MerkleMountainBelt() = MerkleMountainBelt(
   MerkleMountainRange(),
   Vector{Vector{Tuple{ServiceId, Hash}}}()
)

"""
append accumulation output to belt
"""
function belt_append!(belt::MerkleMountainBelt, service::ServiceId, output::Hash)
   # create leaf hash from service and output
   leaf_data = Vector{UInt8}(undef, 36)
   service_bytes = encode_uint32(service)
   copyto!(leaf_data, 1, service_bytes, 1, 4)
   copyto!(leaf_data, 5, output, 1, 32)

   hash_input = Vector{UInt8}(undef, 42)
   accout_prefix = b"accout"
   copyto!(hash_input, 1, accout_prefix, 1, 6)
   copyto!(hash_input, 7, leaf_data, 1, 36)
   leaf = Hash(keccak256(hash_input))
   
   # append to underlying mmr
   mmr_append!(belt.mmr, leaf)
   
   # track the accumulation output
   if isempty(belt.accumulation_outputs)
       push!(belt.accumulation_outputs, [(service, output)])
   else
       push!(last(belt.accumulation_outputs), (service, output))
   end
end

"""
get belt superpeak for commitment
"""
function belt_superpeak(belt::MerkleMountainBelt)::Hash
   mmr_superpeak(belt.mmr)
end

"""
encode belt for serialization
"""
function belt_encode(belt::MerkleMountainBelt)::Vector{UInt8}
   mmr_encode(belt.mmr)
end

# helper to encode uint32 as 4 bytes big-endian
function encode_uint32(n::UInt32)::Vector{UInt8}
   [
       UInt8((n >> 24) & 0xff),
       UInt8((n >> 16) & 0xff),
       UInt8((n >> 8) & 0xff),
       UInt8(n & 0xff)
   ]
end

# helper to encode uint64 as 8 bytes big-endian
function encode_uint64(n::UInt64)::Vector{UInt8}
   [
       UInt8((n >> 56) & 0xff),
       UInt8((n >> 48) & 0xff),
       UInt8((n >> 40) & 0xff),
       UInt8((n >> 32) & 0xff),
       UInt8((n >> 24) & 0xff),
       UInt8((n >> 16) & 0xff),
       UInt8((n >> 8) & 0xff),
       UInt8(n & 0xff)
   ]
end

export MerkleMountainRange, mmr_append!, mmr_encode, mmr_superpeak, mmr_size, mmr_proof
export MerkleMountainBelt, belt_append!, belt_superpeak, belt_encode
export keccak256, encode_uint32, encode_uint64
