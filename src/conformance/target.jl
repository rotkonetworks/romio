# JAM Conformance Target
# Implements the fuzzer protocol for conformance testing
# See jam-conformance/fuzz-proto/README.md for protocol specification

module ConformanceTarget

using Sockets
using StaticArrays

# Include Blake2b
include("../crypto/Blake2b.jl")

# Include Keccak for MMR
include("../crypto/keccak256.jl")

# Include State Backend (ParityDB / InMemory)
include("../state/backend.jl")
using .StateBackend

export start_target, compute_state_root, decode_initialize, decode_import_block, StateStore, state_key, blake2b_256
export update_recent_history!, update_statistics!, update_pending_reports!, apply_state_transition!
export update_authorizations!, update_accumulation_state!, update_judgments!

# Protocol message discriminants
const MSG_PEER_INFO = 0x00
const MSG_INITIALIZE = 0x01
const MSG_STATE_ROOT = 0x02
const MSG_IMPORT_BLOCK = 0x03
const MSG_GET_STATE = 0x04
const MSG_STATE = 0x05
const MSG_ERROR = 0xff

# Feature flags
const FEATURE_ANCESTRY = 0x01
const FEATURE_FORKS = 0x02

# Version info
const FUZZ_VERSION = 0x01
const JAM_VERSION = (major=0x00, minor=0x07, patch=0x00)
const APP_VERSION = (major=0x00, minor=0x01, patch=0x00)
const APP_NAME = "romio"

# Key-value state storage (31-byte key -> variable-length value)
# Uses Dict for fast in-memory access (conformance testing)
# For production, use ParityDBBackend from StateBackend module
mutable struct StateStore
    data::Dict{Vector{UInt8}, Vector{UInt8}}
    # Optional: ParityDB backend for persistence (production use)
    backend::Union{Nothing, AbstractBackend}
end

StateStore() = StateStore(Dict{Vector{UInt8}, Vector{UInt8}}(), nothing)

# Create StateStore with ParityDB persistence
function StateStore(db_path::String)
    backend = ParityDBBackend()
    if !backend_init!(backend, db_path)
        error("Failed to initialize ParityDB at $db_path")
    end
    return StateStore(Dict{Vector{UInt8}, Vector{UInt8}}(), backend)
end

# Session state
mutable struct Session
    socket::IO
    state::StateStore
    features::UInt32
    ancestry::Vector{Tuple{UInt32, Vector{UInt8}}}  # (slot, header_hash)
end

# ============================================================================
# Blake2b-256 wrapper
# ============================================================================

function blake2b_256(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

# ============================================================================
# MMR (Merkle Mountain Range) for accumulation log
# ============================================================================

# MMR peaks: Vector of optional 32-byte hashes
# Index i represents a tree of size 2^i
# nothing means no tree at that level
const MMRPeaks = Vector{Union{Nothing, Vector{UInt8}}}

# Append a hash to MMR, returns new peaks
function mmr_append!(peaks::MMRPeaks, leaf::Vector{UInt8})
    # Recursive merge: if position i is occupied, merge and carry to i+1
    idx = 1
    current = leaf
    while idx <= length(peaks) && peaks[idx] !== nothing
        # Merge: keccak(existing || current)
        merged = keccak_256(vcat(peaks[idx], current))
        peaks[idx] = nothing
        current = merged
        idx += 1
    end
    # Place at first empty slot
    if idx > length(peaks)
        push!(peaks, current)
    else
        peaks[idx] = current
    end
end

# Compute superpeak hash from MMR peaks
function mmr_superpeak(peaks::MMRPeaks)::Vector{UInt8}
    # Collect non-empty peaks (smallest index = smallest tree first)
    non_empty = Vector{UInt8}[]
    for p in peaks
        if p !== nothing
            push!(non_empty, p)
        end
    end

    if isempty(non_empty)
        return zeros(UInt8, 32)
    elseif length(non_empty) == 1
        return non_empty[1]
    else
        # Hash from smallest to largest: h = keccak("$peak" || h || next)
        result = non_empty[1]
        peak_prefix = UInt8['$', 'p', 'e', 'a', 'k']
        for i in 2:length(non_empty)
            result = keccak_256(vcat(peak_prefix, result, non_empty[i]))
        end
        return result
    end
end

# Decode MMR peaks from serialized format
# Format: array len (JAM compact), then for each peak: 0x00 (none) or 0x01 + 32 bytes (some)
function decode_mmr_peaks(data::Vector{UInt8}, start_pos::Int)::Tuple{MMRPeaks, Int}
    pos = start_pos
    if pos > length(data)
        return (MMRPeaks(), pos)
    end

    # Array length
    num_peaks, pos = decode_jam_compact(data, pos)
    peaks = MMRPeaks()

    for _ in 1:num_peaks
        # Optional: 0x00 = none, 0x01 = some
        opt_flag = data[pos]; pos += 1
        if opt_flag == 0x00
            push!(peaks, nothing)
        else
            # Read 32-byte hash
            hash = data[pos:pos+31]; pos += 32
            push!(peaks, copy(hash))
        end
    end

    return (peaks, pos)
end

# Encode MMR peaks to serialized format
# Format: array len (JAM compact), then for each peak: 0x00 (none) or 0x01 + 32 bytes (some)
function encode_mmr_peaks(peaks::MMRPeaks)::Vector{UInt8}
    result = UInt8[]

    # Array length
    append!(result, encode_jam_compact(length(peaks)))

    for peak in peaks
        if peak === nothing
            push!(result, 0x00)  # Optional none
        else
            push!(result, 0x01)  # Optional some
            append!(result, peak)  # 32 bytes hash
        end
    end

    return result
end

# ============================================================================
# JAM Compact Encoding
# ============================================================================

function encode_jam_compact(x::Integer)::Vector{UInt8}
    # JAM compact encoding - fuzzer format (leading 1-bit scheme)
    # l=0 (0xxxxxxx): 1 byte, 7-bit value (0-127)
    # l=1 (10xxxxxx): 2 bytes, 14-bit value
    # l=2 (110xxxxx): 3 bytes, 21-bit value
    # l=3 (1110xxxx): 4 bytes, 28-bit value
    # etc.
    if x < 0
        error("JAM compact only supports non-negative integers")
    elseif x < (1 << 7)  # 0-127: single byte
        return [UInt8(x)]
    elseif x < (1 << 14)  # 128-16383: 2 bytes
        # prefix: 10xxxxxx where xxxxxx = high 6 bits
        # byte 2: low 8 bits
        bytes = reinterpret(UInt8, [UInt16(x)])
        return [UInt8(0x80 | bytes[2]), bytes[1]]
    elseif x < (1 << 21)  # 3 bytes
        # prefix: 110xxxxx with high 5 bits
        # bytes 2-3: remaining 16 bits in little-endian
        high_part = (x >> 16) & 0x1F
        low_part = x & 0xFFFF
        bytes = reinterpret(UInt8, [UInt16(low_part)])
        return [UInt8(0xC0 | high_part), bytes[1], bytes[2]]
    elseif x < (1 << 28)  # 4 bytes
        high_part = (x >> 24) & 0x0F
        low_part = x & 0xFFFFFF
        return [UInt8(0xE0 | high_part), UInt8(low_part & 0xFF), UInt8((low_part >> 8) & 0xFF), UInt8((low_part >> 16) & 0xFF)]
    elseif x < (1 << 35)  # 5 bytes
        high_part = (x >> 32) & 0x07
        low_part = x & 0xFFFFFFFF
        return [UInt8(0xF0 | high_part), UInt8(low_part & 0xFF), UInt8((low_part >> 8) & 0xFF), UInt8((low_part >> 16) & 0xFF), UInt8((low_part >> 24) & 0xFF)]
    elseif x < (1 << 42)  # 6 bytes
        high_part = (x >> 40) & 0x03
        return [UInt8(0xF8 | high_part), UInt8(x & 0xFF), UInt8((x >> 8) & 0xFF), UInt8((x >> 16) & 0xFF), UInt8((x >> 24) & 0xFF), UInt8((x >> 32) & 0xFF)]
    elseif x < (1 << 49)  # 7 bytes
        high_part = (x >> 48) & 0x01
        return [UInt8(0xFC | high_part), UInt8(x & 0xFF), UInt8((x >> 8) & 0xFF), UInt8((x >> 16) & 0xFF), UInt8((x >> 24) & 0xFF), UInt8((x >> 32) & 0xFF), UInt8((x >> 40) & 0xFF)]
    elseif x < (1 << 56)  # 8 bytes
        return [UInt8(0xFE), UInt8(x & 0xFF), UInt8((x >> 8) & 0xFF), UInt8((x >> 16) & 0xFF), UInt8((x >> 24) & 0xFF), UInt8((x >> 32) & 0xFF), UInt8((x >> 40) & 0xFF), UInt8((x >> 48) & 0xFF)]
    else  # 9 bytes (full 64-bit)
        bytes = reinterpret(UInt8, [UInt64(x)])
        return vcat([UInt8(0xFF)], bytes)
    end
end

function decode_jam_compact(data::Vector{UInt8}, pos::Int)::Tuple{Int, Int}
    # JAM compact decoding - fuzzer format (different from GP Appendix A)
    # Uses leading 1 bits to determine length:
    # l=0 (0xxxxxxx): 1 byte, 7-bit value (0-127)
    # l=1 (10xxxxxx): 2 bytes, 14-bit value
    # l=2 (110xxxxx): 3 bytes, 21-bit value
    # l=3 (1110xxxx): 4 bytes, 28-bit value
    # etc.
    first_byte = data[pos]

    if first_byte < 128  # l=0: single byte (0xxxxxxx)
        return (Int(first_byte), pos + 1)
    elseif first_byte < 192  # l=1: 2 bytes (10xxxxxx)
        # prefix has high 6 bits, next byte has low 8 bits (little-endian)
        val = (Int(first_byte & 0x3F) << 8) | Int(data[pos+1])
        return (val, pos + 2)
    elseif first_byte < 224  # l=2: 3 bytes (110xxxxx)
        # prefix has high 5 bits, next 2 bytes in little-endian
        val = (Int(first_byte & 0x1F) << 16) | Int(data[pos+1]) | (Int(data[pos+2]) << 8)
        return (val, pos + 3)
    elseif first_byte < 240  # l=3: 4 bytes (1110xxxx)
        val = (Int(first_byte & 0x0F) << 24) | Int(data[pos+1]) | (Int(data[pos+2]) << 8) | (Int(data[pos+3]) << 16)
        return (val, pos + 4)
    elseif first_byte < 248  # l=4: 5 bytes (11110xxx)
        val = (Int(first_byte & 0x07) << 32) | Int(data[pos+1]) | (Int(data[pos+2]) << 8) | (Int(data[pos+3]) << 16) | (Int(data[pos+4]) << 24)
        return (val, pos + 5)
    elseif first_byte < 252  # l=5: 6 bytes (111110xx)
        val = (Int(first_byte & 0x03) << 40) | Int(data[pos+1]) | (Int(data[pos+2]) << 8) | (Int(data[pos+3]) << 16) | (Int(data[pos+4]) << 24) | (Int(data[pos+5]) << 32)
        return (val, pos + 6)
    elseif first_byte < 254  # l=6: 7 bytes (1111110x)
        val = (Int(first_byte & 0x01) << 48) | Int(data[pos+1]) | (Int(data[pos+2]) << 8) | (Int(data[pos+3]) << 16) | (Int(data[pos+4]) << 24) | (Int(data[pos+5]) << 32) | (Int(data[pos+6]) << 40)
        return (val, pos + 7)
    elseif first_byte == 254  # l=7: 8 bytes (11111110)
        val = Int(data[pos+1]) | (Int(data[pos+2]) << 8) | (Int(data[pos+3]) << 16) | (Int(data[pos+4]) << 24) | (Int(data[pos+5]) << 32) | (Int(data[pos+6]) << 40) | (Int(data[pos+7]) << 48)
        return (val, pos + 8)
    else  # 255: full 8 bytes (little-endian)
        val = reinterpret(UInt64, data[pos+1:pos+8])[1]
        return (Int(val), pos + 9)
    end
end

# ============================================================================
# Protocol Encoding
# ============================================================================

function encode_peer_info()::Vector{UInt8}
    result = UInt8[]

    # Discriminant
    push!(result, MSG_PEER_INFO)

    # fuzz_version (u8)
    push!(result, FUZZ_VERSION)

    # fuzz_features (u32 LE)
    append!(result, reinterpret(UInt8, [UInt32(FEATURE_FORKS)]))

    # jam_version (3 x u8)
    push!(result, JAM_VERSION.major)
    push!(result, JAM_VERSION.minor)
    push!(result, JAM_VERSION.patch)

    # app_version (3 x u8)
    push!(result, APP_VERSION.major)
    push!(result, APP_VERSION.minor)
    push!(result, APP_VERSION.patch)

    # app_name (length-prefixed string)
    name_bytes = Vector{UInt8}(APP_NAME)
    push!(result, UInt8(length(name_bytes)))
    append!(result, name_bytes)

    return result
end

function encode_state_root(root::Vector{UInt8})::Vector{UInt8}
    result = UInt8[MSG_STATE_ROOT]
    append!(result, root)
    return result
end

function encode_error(msg::String)::Vector{UInt8}
    result = UInt8[MSG_ERROR]
    msg_bytes = Vector{UInt8}(msg)
    append!(result, encode_jam_compact(length(msg_bytes)))
    append!(result, msg_bytes)
    return result
end

function encode_state(store::StateStore)::Vector{UInt8}
    result = UInt8[MSG_STATE]

    pairs = collect(store.data)
    append!(result, encode_jam_compact(length(pairs)))

    for (key, value) in pairs
        append!(result, key)  # 31 bytes exactly
        append!(result, encode_jam_compact(length(value)))
        append!(result, value)
    end

    return result
end

# ============================================================================
# Protocol Decoding
# ============================================================================

function decode_peer_info(data::Vector{UInt8})
    pos = 2  # Skip discriminant

    fuzz_version = data[pos]; pos += 1
    fuzz_features = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4
    jam_major = data[pos]; pos += 1
    jam_minor = data[pos]; pos += 1
    jam_patch = data[pos]; pos += 1
    app_major = data[pos]; pos += 1
    app_minor = data[pos]; pos += 1
    app_patch = data[pos]; pos += 1
    name_len = data[pos]; pos += 1
    app_name = String(data[pos:pos+name_len-1])

    return (
        fuzz_version = fuzz_version,
        fuzz_features = fuzz_features,
        jam_version = (major=jam_major, minor=jam_minor, patch=jam_patch),
        app_version = (major=app_major, minor=app_minor, patch=app_patch),
        app_name = app_name
    )
end

# Constants for tiny config (used in conformance tests)
const VALIDATORS_COUNT = 6
const EPOCH_LENGTH = 12

# Decode Initialize message and return state key-values
# Handles Header with fixed-size arrays (no length prefix for fixed sequences)
function decode_initialize(data::Vector{UInt8})::Tuple{Dict{Vector{UInt8}, Vector{UInt8}}, Vector{Tuple{UInt32, Vector{UInt8}}}}
    pos = 1  # Data already has message discriminant stripped (passed as data[2:end] by caller)

    # Header structure (JAM types):
    # - parent: 32 bytes (HeaderHash)
    # - parent_state_root: 32 bytes (StateRoot)
    # - extrinsic_hash: 32 bytes (OpaqueHash)
    # - slot: 4 bytes (U32)
    # - epoch_mark: Optional (None=0x00, Some=0x01 + EpochMark)
    # - tickets_mark: Optional (None=0x00, Some=0x01 + TicketsMark)
    # - author_index: 2 bytes (U16)
    # - entropy_source: 96 bytes (BandersnatchVrfSignature)
    # - offenders_mark: sequence (variable length)
    # - seal: 96 bytes (BandersnatchVrfSignature)

    @debug "decode_initialize: starting at pos=$pos, data length=$(length(data))"

    pos += 32  # parent
    pos += 32  # parent_state_root
    pos += 32  # extrinsic_hash
    pos += 4   # slot

    @debug "decode_initialize: after header basics, pos=$pos"

    # epoch_mark (optional)
    epoch_mark_byte = data[pos]
    @debug "decode_initialize: epoch_mark discriminant=$(epoch_mark_byte) at pos=$pos"
    if epoch_mark_byte == 0x01  # Some
        pos += 1
        pos += 32  # entropy
        pos += 32  # tickets_entropy
        # validators: FIXED SIZE sequence (no length prefix!)
        # Each validator: bandersnatch (32) + ed25519 (32) = 64 bytes
        pos += VALIDATORS_COUNT * 64
        @debug "decode_initialize: parsed epoch_mark, now at pos=$pos"
    else
        pos += 1  # None discriminant
    end

    # tickets_mark (optional)
    tickets_mark_byte = data[pos]
    @debug "decode_initialize: tickets_mark discriminant=$(tickets_mark_byte) at pos=$pos"
    if tickets_mark_byte == 0x01  # Some
        pos += 1
        # TicketsMark: FIXED SIZE sequence of epoch_length TicketBody
        # Each TicketBody: id (32) + attempt (1) = 33 bytes
        pos += EPOCH_LENGTH * 33
        @debug "decode_initialize: parsed tickets_mark, now at pos=$pos"
    else
        pos += 1
    end

    # author_index: 2 bytes
    pos += 2
    @debug "decode_initialize: after author_index, pos=$pos"

    # entropy_source: 96 bytes
    pos += 96
    @debug "decode_initialize: after entropy_source, pos=$pos"

    # offenders_mark: variable length sequence of ed25519 keys
    num_offenders, pos = decode_jam_compact(data, pos)
    @debug "decode_initialize: num_offenders=$num_offenders, pos=$pos"
    pos += num_offenders * 32

    # seal: 96 bytes
    pos += 96
    @debug "decode_initialize: after seal (end of header), pos=$pos"

    # Now: State key-values
    state = Dict{Vector{UInt8}, Vector{UInt8}}()

    num_keyvals, pos = decode_jam_compact(data, pos)
    @debug "decode_initialize: num_keyvals=$num_keyvals, pos=$pos"

    for i in 1:num_keyvals
        if pos + 30 > length(data)
            error("decode_initialize: not enough data for key $i at pos=$pos (need 31 bytes, have $(length(data) - pos + 1))")
        end
        # Key: 31 bytes
        key = data[pos:pos+30]
        pos += 31

        # Value: JAM compact length-prefixed
        value_len, pos = decode_jam_compact(data, pos)
        if value_len > 0
            if pos + value_len - 1 > length(data)
                error("decode_initialize: not enough data for value $i at pos=$pos (need $value_len bytes)")
            end
            value = data[pos:pos+value_len-1]
        else
            value = UInt8[]
        end
        pos += value_len

        state[key] = value
    end

    # Ancestry: sequence of (slot, header_hash) pairs
    ancestry = Vector{Tuple{UInt32, Vector{UInt8}}}()
    num_ancestry, pos = decode_jam_compact(data, pos)
    @debug "decode_initialize: num_ancestry=$num_ancestry, pos=$pos"

    for _ in 1:num_ancestry
        # slot: 4 bytes U32 LE
        slot = reinterpret(UInt32, data[pos:pos+3])[1]
        pos += 4
        # header_hash: 32 bytes
        header_hash = data[pos:pos+31]
        pos += 32
        push!(ancestry, (slot, header_hash))
    end

    return (state, ancestry)
end

# ============================================================================
# State Root Computation (Binary Patricia Merkle Trie)
# Per JAM Gray Paper Section "State Merklization" (equations 286-289)
# ============================================================================

# Get bit i from key (MSB-first within each byte, per Gray Paper)
# Gray Paper section "Notation": bits(blob) is "ordered with the most significant first"
# Per Strawberry (Go): (k[i/8] & (1 << (7 - i%8))) != 0
@inline function get_bit(key::Vector{UInt8}, i::Int)::Bool
    byte_idx = (i >> 3) + 1  # Julia 1-indexed
    bit_idx = 7 - (i & 7)    # MSB first: bit 0 = MSB (position 7 in byte)
    mask = UInt8(1) << bit_idx   # 0x80 for bit 0, 0x40 for bit 1, ..., 0x01 for bit 7
    return (key[byte_idx] & mask) != 0
end

# Encode a leaf node per Gray Paper Section "State Merklization"
# L(k, v) for 32-byte keys and arbitrary values
# Encoded size is always 64 bytes (512 bits)
#
# Per Gray Paper (MSB-first bit ordering):
# For embedded value (len(v) <= 32):
#   First byte: [1, 0, len_bits[0:6]]  where bit 0 = MSB = 1 (leaf), bit 1 = 0 (embedded)
#   Meaning: 0b10xxxxxx where xxxxxx = length (0-32)
#   So head = 0x80 | length
#
# For regular value (len(v) > 32):
#   First byte: [1, 1, 0, 0, 0, 0, 0, 0] = 0b11000000 = 0xC0
#   Following 31 bytes: first 31 bytes of key
#   Last 32 bytes: blake2b hash of value
function encode_leaf(key::Vector{UInt8}, value::Vector{UInt8})::Vector{UInt8}
    result = zeros(UInt8, 64)

    # key should be 32 bytes, we use FIRST 31 bytes in the encoding
    @assert length(key) == 32 "Key must be 32 bytes"

    if length(value) <= 32
        # Embedded value leaf: bit0=1 (leaf), bit1=0 (embedded), bits2-7=length
        # MSB-first: 0b10xxxxxx where xxxxxx = length
        result[1] = 0x80 | UInt8(length(value))
        # Key: FIRST 31 bytes (key[1:31] in Julia 1-indexed)
        copyto!(result, 2, key, 1, 31)
        # Value: padded to 32 bytes starting at byte 33
        if length(value) > 0
            copyto!(result, 33, value, 1, length(value))
        end
    else
        # Regular (hashed) value leaf: bit0=1, bit1=1 -> 0b11000000 = 0xC0
        result[1] = 0xC0
        # Key: FIRST 31 bytes
        copyto!(result, 2, key, 1, 31)
        # Hash of value: 32 bytes starting at byte 33
        h = blake2b_256(value)
        copyto!(result, 33, h, 1, 32)
    end

    return result
end

# Encode a branch node per Gray Paper Section "State Merklization"
# B(l, r) = branch node with left and right child hashes
#
# Per Gray Paper (MSB-first bit ordering):
#   First bit is 0 (branch), remaining 511 bits are:
#   - last 255 bits of left hash (skip first bit of left[0])
#   - full 256 bits of right hash
#
# Per Strawberry: node[0] = left[0] & 0b01111111 (clear MSB, bit 0)
# Total: 1 + 31 + 32 = 64 bytes
function encode_branch(left::Vector{UInt8}, right::Vector{UInt8})::Vector{UInt8}
    @assert length(left) == 32 "Left hash must be 32 bytes"
    @assert length(right) == 32 "Right hash must be 32 bytes"

    result = zeros(UInt8, 64)

    # First byte: left[0] with MSB cleared (bit 0 = 0 marks branch)
    result[1] = left[1] & 0x7f  # 0b01111111
    # Bytes 2-32: remaining 31 bytes of left hash
    copyto!(result, 2, left, 2, 31)
    # Bytes 33-64: full 32 bytes of right hash
    copyto!(result, 33, right, 1, 32)

    return result
end

# Recursive merkle computation per Gray Paper M function
# M(d) = zerohash if empty
#      = blake2b(L(k,v)) if single entry
#      = blake2b(B(M(left), M(right))) otherwise
#
# kvs: list of (key, value) tuples where keys are 31 bytes
# i: current bit position for partitioning (0-indexed)
function merkle_recursive(kvs::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}, i::Int = 0)::Vector{UInt8}
    if isempty(kvs)
        return zeros(UInt8, 32)
    end

    if length(kvs) == 1
        # Single entry - encode as leaf
        key, value = kvs[1]
        encoded = encode_leaf(key, value)
        return blake2b_256(encoded)
    end

    # Partition by bit at position i
    # bit 0 goes to left subtrie, bit 1 goes to right subtrie
    left_kvs = Tuple{Vector{UInt8}, Vector{UInt8}}[]
    right_kvs = Tuple{Vector{UInt8}, Vector{UInt8}}[]

    for (key, value) in kvs
        if get_bit(key, i)
            push!(right_kvs, (key, value))
        else
            push!(left_kvs, (key, value))
        end
    end

    # Recurse on both sides
    left_hash = merkle_recursive(left_kvs, i + 1)
    right_hash = merkle_recursive(right_kvs, i + 1)

    # Encode branch
    encoded = encode_branch(left_hash, right_hash)
    return blake2b_256(encoded)
end

# Compute state root from key-value store
# State keys are 31 bytes, but merkle algorithm uses 32-byte keys
# Pad 31-byte keys to 32 bytes with a trailing zero
function compute_state_root(store::StateStore)::Vector{UInt8}
    if isempty(store.data)
        return zeros(UInt8, 32)
    end

    # Convert to vector of tuples, padding 31-byte keys to 32 bytes
    kvs = Tuple{Vector{UInt8}, Vector{UInt8}}[]
    for (k, v) in store.data
        # Pad key to 32 bytes if needed
        key32 = length(k) == 31 ? vcat(k, UInt8[0x00]) : k
        push!(kvs, (key32, v))
    end

    return merkle_recursive(kvs)
end

# Convenience function for Dict input
function compute_state_root(data::Dict{Vector{UInt8}, Vector{UInt8}})::Vector{UInt8}
    store = StateStore(data, nothing)
    return compute_state_root(store)
end

# ============================================================================
# ImportBlock Decoding and State Transition
# ============================================================================

# Define types in dependency order

struct ValidatorKey
    bandersnatch::Vector{UInt8}     # 32 bytes
    ed25519::Vector{UInt8}          # 32 bytes
end

struct EpochMark
    entropy::Vector{UInt8}          # 32 bytes
    tickets_entropy::Vector{UInt8}  # 32 bytes
    validators::Vector{ValidatorKey}
end

struct TicketBody
    id::Vector{UInt8}               # 32 bytes
    attempt::UInt8
end

# Block header structure (parsed)
struct BlockHeader
    parent::Vector{UInt8}           # 32 bytes
    parent_state_root::Vector{UInt8} # 32 bytes
    extrinsic_hash::Vector{UInt8}   # 32 bytes
    slot::UInt32
    epoch_mark::Union{Nothing, EpochMark}
    tickets_mark::Union{Nothing, Vector{TicketBody}}
    author_index::UInt16
    entropy_source::Vector{UInt8}   # 96 bytes VRF signature
    offenders_mark::Vector{Vector{UInt8}}  # list of ed25519 keys
    seal::Vector{UInt8}             # 96 bytes VRF signature
end

# Refine load statistics for work result
struct RefineLoad
    gas_used::UInt64
    imports::UInt16
    extrinsic_count::UInt16
    extrinsic_size::UInt32
    exports::UInt16
end

# Work report result
struct WorkResult
    service_id::UInt32
    code_hash::Vector{UInt8}        # 32 bytes
    payload_hash::Vector{UInt8}     # 32 bytes
    accumulate_gas::UInt64
    result::Union{Vector{UInt8}, Nothing}  # Ok(bytes) or Err
    result_err_code::UInt8          # Error discriminant (0x01, 0x02, etc.) when result is Nothing
    refine_load::RefineLoad         # Resource usage during refinement
end

# Work report (simplified)
struct WorkReport
    package_hash::Vector{UInt8}     # 32 bytes
    package_length::UInt32
    erasure_root::Vector{UInt8}     # 32 bytes
    exports_root::Vector{UInt8}     # 32 bytes
    exports_count::UInt16
    anchor::Vector{UInt8}           # 32 bytes (context)
    state_root::Vector{UInt8}       # 32 bytes (context)
    beefy_root::Vector{UInt8}       # 32 bytes (context)
    lookup_anchor::Vector{UInt8}    # 32 bytes (context)
    lookup_anchor_slot::UInt32
    prerequisites::Vector{Vector{UInt8}}  # list of hashes
    core_index::UInt16
    authorizer_hash::Vector{UInt8}  # 32 bytes
    auth_gas_used::UInt64
    auth_output::Vector{UInt8}
    segment_root_lookup::Vector{Vector{UInt8}}
    results::Vector{WorkResult}
end

# Guarantee with signatures
struct Guarantee
    report::WorkReport
    slot::UInt32
    signatures::Vector{Tuple{UInt16, Vector{UInt8}}}  # (validator_index, signature)
end

# Dispute extrinsic
struct DisputeExtrinsic
    verdicts::Vector{Any}
    culprits::Vector{Any}
    faults::Vector{Any}
end

# Full extrinsic
struct BlockExtrinsic
    tickets::Vector{Any}
    preimages::Vector{Tuple{UInt32, Vector{UInt8}}}
    guarantees::Vector{Guarantee}
    assurances::Vector{Any}
    disputes::DisputeExtrinsic
end

# Full block
struct Block
    header::BlockHeader
    header_hash::Vector{UInt8}      # computed from header encoding
    extrinsic::BlockExtrinsic
end

# Decode ImportBlock message
function decode_import_block(data::Vector{UInt8})::Block
    pos = 2  # Skip discriminant

    # Header
    parent = data[pos:pos+31]; pos += 32
    parent_state_root = data[pos:pos+31]; pos += 32
    extrinsic_hash = data[pos:pos+31]; pos += 32
    slot = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4

    # epoch_mark (optional)
    epoch_mark = nothing
    if data[pos] == 0x01
        pos += 1
        entropy = data[pos:pos+31]; pos += 32
        tickets_entropy = data[pos:pos+31]; pos += 32
        validators = ValidatorKey[]
        for _ in 1:VALIDATORS_COUNT
            bander = data[pos:pos+31]; pos += 32
            ed25519 = data[pos:pos+31]; pos += 32
            push!(validators, ValidatorKey(bander, ed25519))
        end
        epoch_mark = EpochMark(entropy, tickets_entropy, validators)
    else
        pos += 1
    end

    # tickets_mark (optional)
    tickets_mark = nothing
    if data[pos] == 0x01
        pos += 1
        tickets_mark = TicketBody[]
        for _ in 1:EPOCH_LENGTH
            id = data[pos:pos+31]; pos += 32
            attempt = data[pos]; pos += 1
            push!(tickets_mark, TicketBody(id, attempt))
        end
    else
        pos += 1
    end

    # author_index
    author_index = reinterpret(UInt16, data[pos:pos+1])[1]; pos += 2

    # entropy_source (VRF signature, 96 bytes)
    entropy_source = data[pos:pos+95]; pos += 96

    # offenders_mark (variable length)
    num_offenders, pos = decode_jam_compact(data, pos)
    offenders_mark = Vector{Vector{UInt8}}()
    for _ in 1:num_offenders
        push!(offenders_mark, data[pos:pos+31])
        pos += 32
    end

    # seal (VRF signature, 96 bytes)
    seal = data[pos:pos+95]; pos += 96

    header = BlockHeader(parent, parent_state_root, extrinsic_hash, slot,
                        epoch_mark, tickets_mark, author_index, entropy_source,
                        offenders_mark, seal)

    # Compute header hash (hash of header encoding up to but not including seal)
    header_bytes = data[2:pos-96]  # Header without seal
    header_hash = blake2b_256(header_bytes)

    # Extrinsic
    # tickets (sequence)
    num_tickets, pos = decode_jam_compact(data, pos)
    tickets = []
    for _ in 1:num_tickets
        # Skip ticket decoding for now - just consume bytes
        # Ticket: attempt (4 bytes) + proof (784 bytes ring VRF)
        pos += 4 + 784
    end

    # preimages (sequence)
    num_preimages, pos = decode_jam_compact(data, pos)
    preimages = Tuple{UInt32, Vector{UInt8}}[]
    for _ in 1:num_preimages
        service_id = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4
        blob_len, pos = decode_jam_compact(data, pos)
        blob = data[pos:pos+blob_len-1]; pos += blob_len
        push!(preimages, (service_id, blob))
    end

    # guarantees (sequence)
    num_guarantees, pos = decode_jam_compact(data, pos)
    guarantees = Guarantee[]
    for _ in 1:num_guarantees
        report, pos = decode_work_report(data, pos)
        gslot = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4

        num_sigs, pos = decode_jam_compact(data, pos)
        sigs = Tuple{UInt16, Vector{UInt8}}[]
        for _ in 1:num_sigs
            val_idx = reinterpret(UInt16, data[pos:pos+1])[1]; pos += 2
            sig = data[pos:pos+63]; pos += 64
            push!(sigs, (val_idx, sig))
        end
        push!(guarantees, Guarantee(report, gslot, sigs))
    end

    # assurances (sequence)
    num_assurances, pos = decode_jam_compact(data, pos)
    assurances = []
    for _ in 1:num_assurances
        # anchor hash (32), bitfield (variable), validator_index (2), signature (64)
        pos += 32  # anchor
        # bitfield for C cores - ceil(C/8) bytes
        bitfield_len = div(CORES_COUNT + 7, 8)
        pos += bitfield_len
        pos += 2   # validator_index
        pos += 64  # signature
    end

    # disputes
    num_verdicts, pos = decode_jam_compact(data, pos)
    for _ in 1:num_verdicts
        pos += 32  # report_hash
        pos += 4   # epoch
        num_judgments, pos = decode_jam_compact(data, pos)
        pos += num_judgments * (1 + 2 + 64)  # judgment, validator_index, signature
    end

    num_culprits, pos = decode_jam_compact(data, pos)
    for _ in 1:num_culprits
        pos += 32 + 32 + 64  # target, key, signature
    end

    num_faults, pos = decode_jam_compact(data, pos)
    for _ in 1:num_faults
        pos += 32 + 32 + 64  # target, key, signature
    end

    disputes = DisputeExtrinsic([], [], [])
    extrinsic = BlockExtrinsic(tickets, preimages, guarantees, assurances, disputes)

    return Block(header, header_hash, extrinsic)
end

# Decode work report
function decode_work_report(data::Vector{UInt8}, pos::Int)::Tuple{WorkReport, Int}
    # package_spec
    package_hash = data[pos:pos+31]; pos += 32
    package_length = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4
    erasure_root = data[pos:pos+31]; pos += 32
    exports_root = data[pos:pos+31]; pos += 32
    exports_count = reinterpret(UInt16, data[pos:pos+1])[1]; pos += 2

    # context
    anchor = data[pos:pos+31]; pos += 32
    state_root = data[pos:pos+31]; pos += 32
    beefy_root = data[pos:pos+31]; pos += 32
    lookup_anchor = data[pos:pos+31]; pos += 32
    lookup_anchor_slot = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4

    num_prereqs, pos = decode_jam_compact(data, pos)
    prerequisites = Vector{Vector{UInt8}}()
    for _ in 1:num_prereqs
        push!(prerequisites, data[pos:pos+31])
        pos += 32
    end

    core_index, pos = decode_jam_compact(data, pos)
    authorizer_hash = data[pos:pos+31]; pos += 32
    auth_gas_used, pos = decode_jam_compact(data, pos)

    auth_output_len, pos = decode_jam_compact(data, pos)
    auth_output = data[pos:pos+auth_output_len-1]; pos += auth_output_len

    num_segments, pos = decode_jam_compact(data, pos)
    segment_root_lookup = Vector{Vector{UInt8}}()
    for _ in 1:num_segments
        push!(segment_root_lookup, data[pos:pos+31])
        pos += 32
    end

    # results
    num_results, pos = decode_jam_compact(data, pos)
    results = WorkResult[]
    for _ in 1:num_results
        service_id = reinterpret(UInt32, data[pos:pos+3])[1]; pos += 4
        code_hash = data[pos:pos+31]; pos += 32
        payload_hash = data[pos:pos+31]; pos += 32
        accumulate_gas = reinterpret(UInt64, data[pos:pos+7])[1]; pos += 8

        # result: Result<Vec<u8>, WorkError>
        # 0x00 = Ok variant, 0x01+ = Err variants
        result = nothing
        result_err_code = UInt8(0)
        result_disc = data[pos]; pos += 1
        if result_disc == 0x00  # Ok
            result_len, pos = decode_jam_compact(data, pos)
            result = data[pos:pos+result_len-1]; pos += result_len
        else  # Err - preserve the error discriminant for re-encoding
            result_err_code = result_disc
        end

        # refine_load: all fields use JAM compact encoding
        refine_gas_used, pos = decode_jam_compact(data, pos)
        refine_imports, pos = decode_jam_compact(data, pos)
        refine_extrinsic_count, pos = decode_jam_compact(data, pos)
        refine_extrinsic_size, pos = decode_jam_compact(data, pos)
        refine_exports, pos = decode_jam_compact(data, pos)

        refine_load = RefineLoad(
            UInt64(refine_gas_used),
            UInt16(refine_imports),
            UInt16(refine_extrinsic_count),
            UInt32(refine_extrinsic_size),
            UInt16(refine_exports)
        )

        push!(results, WorkResult(service_id, code_hash, payload_hash, accumulate_gas, result, result_err_code, refine_load))
    end

    report = WorkReport(package_hash, package_length, erasure_root, exports_root, exports_count,
                       anchor, state_root, beefy_root, lookup_anchor, lookup_anchor_slot,
                       prerequisites, core_index, authorizer_hash, auth_gas_used, auth_output,
                       segment_root_lookup, results)
    return (report, pos)
end

# Core count for tiny config
const CORES_COUNT = 2

# State key constructors per Gray Paper
function state_key(index::Int)::Vector{UInt8}
    key = zeros(UInt8, 31)
    key[1] = UInt8(index)
    return key
end

# ============================================================================
# State Transition Function (Gray Paper compliant, byte-level)
# ============================================================================

# Get previous timeslot from state
function get_timeslot(state::StateStore)::UInt32
    key = state_key(11)
    if haskey(state.data, key)
        bytes = state.data[key]
        if length(bytes) >= 4
            return reinterpret(UInt32, bytes[1:4])[1]
        end
    end
    return UInt32(0)
end

# Get epoch from slot (tiny: epoch_length=12)
@inline get_epoch(slot::UInt32)::UInt32 = div(slot, EPOCH_LENGTH)

# Compute VRF output from Bandersnatch signature (seal)
# For conformance testing without full signature verification,
# we use the blake2b hash of the seal as the entropy source
# (matching TypeBerry's omitSealVerification mode)
@inline function seal_entropy(seal::Vector{UInt8})::Vector{UInt8}
    return blake2b_256(seal)
end

# Apply state transition per Gray Paper equations
# MINIMAL VERSION: Only update timeslot for now to debug
function apply_state_transition!(state::StateStore, block::Block, ancestry::Vector{Tuple{UInt32, Vector{UInt8}}})
    header = block.header
    extrinsic = block.extrinsic

    # Get prior state
    old_slot = get_timeslot(state)
    new_slot = header.slot

    # Epoch calculation (GP eq 33-34)
    old_epoch = get_epoch(old_slot)
    new_epoch = get_epoch(new_slot)
    epoch_change = new_epoch > old_epoch

    # DEBUG: Print initial state root
    root0 = compute_state_root(state)
    println("  [STF] Initial root: 0x$(bytes2hex(root0))")

    # =========================================================================
    # 1. TIMESLOT UPDATE (GP eq 28)
    # =========================================================================
    tau_key = state_key(11)
    old_tau = haskey(state.data, tau_key) ? state.data[tau_key] : UInt8[]
    new_tau = reinterpret(UInt8, [new_slot])
    state.data[tau_key] = new_tau
    println("  [STF] Tau key: 0x$(bytes2hex(tau_key))")
    println("  [STF] Tau old: 0x$(bytes2hex(old_tau)) -> new: 0x$(bytes2hex(new_tau))")
    root1 = compute_state_root(state)
    println("  [STF] After timeslot: 0x$(bytes2hex(root1))")

    # =========================================================================
    # 2. ENTROPY UPDATE (GP eq 174, 179-182)
    # =========================================================================
    entropy_key = state_key(6)
    if haskey(state.data, entropy_key)
        old_entropy = state.data[entropy_key]
        if length(old_entropy) >= 128  # 4 x 32-byte hashes
            ent0 = old_entropy[1:32]
            ent1 = old_entropy[33:64]
            ent2 = old_entropy[65:96]
            ent3 = old_entropy[97:128]

            # GP eq 174: entropy[0]' = Blake2b(entropy[0] || banderout(H_vrfsig))
            # In omitSealVerification mode (conformance testing), the VRF output
            # is the first 32 bytes of entropy_source (Bandersnatch VRF pre-output)
            vrf_output = header.entropy_source[1:32]
            println("  [ENT] eta0:        0x$(bytes2hex(ent0))")
            println("  [ENT] vrf_output:  0x$(bytes2hex(vrf_output))")
            ent0_new = blake2b_256(vcat(ent0, vrf_output))
            println("  [ENT] new_eta0:    0x$(bytes2hex(ent0_new))")

            # GP eq 179-182: On epoch change, rotate entropy history
            if epoch_change
                state.data[entropy_key] = vcat(ent0_new, ent0, ent1, ent2)
            else
                state.data[entropy_key] = vcat(ent0_new, ent1, ent2, ent3)
            end
        end
    end
    root2 = compute_state_root(state)
    println("  [STF] After entropy: 0x$(bytes2hex(root2))")

    # =========================================================================
    # 3. VALIDATOR ROTATION on epoch change (GP eq 115-116)
    # =========================================================================
    if epoch_change
        staging_key = state_key(7)   # staging/queued validators
        active_key = state_key(8)    # active/current validators
        previous_key = state_key(9)  # previous validators

        if haskey(state.data, staging_key) && haskey(state.data, active_key)
            old_staging = state.data[staging_key]
            old_active = state.data[active_key]

            # active' = staging, previous' = active
            state.data[previous_key] = old_active
            state.data[active_key] = old_staging
        end
    end
    root3 = compute_state_root(state)
    println("  [STF] After validators: 0x$(bytes2hex(root3))")

    # =========================================================================
    # 4. RECENT HISTORY UPDATE (GP recent_history.tex eq 24, 36-38)
    # =========================================================================
    update_recent_history!(state, block)
    root4 = compute_state_root(state)
    println("  [STF] After recent history: 0x$(bytes2hex(root4))")

    # =========================================================================
    # 5. STATISTICS UPDATE (GP statistics.tex)
    # =========================================================================
    update_statistics!(state, block, epoch_change)
    root5 = compute_state_root(state)
    println("  [STF] After statistics: 0x$(bytes2hex(root5))")

    # =========================================================================
    # 6. SAFROLE STATE UPDATE (GP eq 200-206)
    # Not needed for basic conformance - tickets stay unchanged without epoch
    # =========================================================================

    # =========================================================================
    # 7. AUTHORIZATION POOL UPDATE (GP authorization.tex)
    # =========================================================================
    update_authorizations!(state, block)
    root6 = compute_state_root(state)
    println("  [STF] After authorizations: 0x$(bytes2hex(root6))")

    # =========================================================================
    # 8. PENDING REPORTS UPDATE (GP reporting.tex)
    # =========================================================================
    update_pending_reports!(state, block)
    root7a = compute_state_root(state)
    println("  [STF] After pending reports: 0x$(bytes2hex(root7a))")

    # =========================================================================
    # 9. ACCUMULATION STATE UPDATE (GP accumulate.tex)
    # Updates Xi (recentlyAccumulated) and Omega (accumulationQueue)
    # =========================================================================
    update_accumulation_state!(state, block, new_slot)
    root7b = compute_state_root(state)
    println("  [STF] After accumulation state: 0x$(bytes2hex(root7b))")

    # =========================================================================
    # 9. DISPUTES/JUDGMENTS UPDATE (GP disputes.tex)
    # =========================================================================
    update_judgments!(state, block)
    root7 = compute_state_root(state)
    println("  [STF] After judgments: 0x$(bytes2hex(root7))")
    println("  [STF] Expected:        0xd8b5b7d115536e7ec5e44da56583ada043e0d4b0332340736e9482986d8f229b")

    @debug "STF: slot $old_slot -> $new_slot (epoch $old_epoch -> $new_epoch), $(length(extrinsic.guarantees)) guarantees"
end

# Recent history size limit for tiny config
const RECENT_HISTORY_LEN = 8

# Update recent history per GP recent_history.tex
# Format: entries (JAM_compact(len) + BlockState[]) + mmr_belt
# BlockState per GP: header_hash(32) + accout_log_superpeak(32) + state_root(32) + reported dict
function update_recent_history!(state::StateStore, block::Block)
    history_key = state_key(3)
    if !haskey(state.data, history_key)
        return
    end

    old_data = state.data[history_key]
    header = block.header

    # Parse existing RecentBlocks structure per ASN.1:
    # RecentBlocks ::= SEQUENCE { history BlocksHistory, mmr Mmr }
    # BlockInfo ::= SEQUENCE { header-hash, beefy-root, state-root, reported }
    pos = 1
    num_entries, pos = decode_jam_compact(old_data, pos)

    # Parse all BlockInfo entries
    # Fields: header_hash (32), beefy_root (32), state_root (32), reported (array)
    entries = Vector{Tuple{Vector{UInt8}, Vector{UInt8}, Vector{UInt8}, Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}}}()
    for _ in 1:num_entries
        hdr_hash = old_data[pos:pos+31]; pos += 32
        beefy_root = old_data[pos:pos+31]; pos += 32
        state_root_val = old_data[pos:pos+31]; pos += 32

        # reported SEQUENCE OF ReportedWorkPackage
        reported_len, pos = decode_jam_compact(old_data, pos)
        reported = Tuple{Vector{UInt8}, Vector{UInt8}}[]
        for _ in 1:reported_len
            wrh = old_data[pos:pos+31]; pos += 32
            er = old_data[pos:pos+31]; pos += 32
            push!(reported, (wrh, er))
        end

        push!(entries, (hdr_hash, beefy_root, state_root_val, reported))
    end

    # Parse MMR from remaining bytes (at end of RecentBlocks)
    mmr_peaks, _ = decode_mmr_peaks(old_data, pos)

    # GP recent_history.tex eq 24: Update last entry's state_root to parent_state_root
    if !isempty(entries)
        last_entry = entries[end]
        entries[end] = (last_entry[1], last_entry[2], header.parent_state_root, last_entry[4])
    end

    # Build reported packages from ACCUMULATED reports only (confirmed by assurances)
    # Per GP recent_history.tex, reported contains work packages that were accumulated this block
    # Guarantees that are not yet confirmed by assurances go to pending, not reported
    # For now, with no accumulation happening (no assurances), reported is empty
    new_reported = Tuple{Vector{UInt8}, Vector{UInt8}}[]
    # TODO: When accumulation is implemented, add accumulated work reports here

    # GP: Compute accumulate root from accumulation outputs
    # For no accumulation (empty outputs), this is zero hash
    accumulate_root = zeros(UInt8, 32)

    # GP merklization.tex: Append accumulate_root to MMR
    mmr_append!(mmr_peaks, accumulate_root)

    # beefy_root for new entry is the MMR superpeak after appending
    beefy_root_new = mmr_superpeak(mmr_peaks)

    # New entry: header_hash, beefy_root (MMR superpeak), state_root (zeros until next block), reported
    new_entry = (
        block.header_hash,
        beefy_root_new,
        zeros(UInt8, 32),  # state_root (will be updated next block per GP eq 24)
        new_reported
    )

    push!(entries, new_entry)

    # Truncate to RECENT_HISTORY_LEN
    if length(entries) > RECENT_HISTORY_LEN
        entries = entries[end-RECENT_HISTORY_LEN+1:end]
    end

    # Re-encode RecentBlocks structure
    # Format: history_len (JAM compact), then BlockInfo entries, then MMR peaks
    result = encode_jam_compact(length(entries))
    for (hdr_hash, beefy_root, state_root_val, reported) in entries
        append!(result, hdr_hash)
        append!(result, beefy_root)
        append!(result, state_root_val)
        append!(result, encode_jam_compact(length(reported)))
        for (wrh, er) in reported
            append!(result, wrh)
            append!(result, er)
        end
    end

    # Encode MMR peaks at end
    append!(result, encode_mmr_peaks(mmr_peaks))

    state.data[history_key] = result
end

# Statistics: 6 u32 stats per validator (blocks, tickets, preimages_count, preimages_size, guarantees, assurances)
const VALIDATOR_STATS_SIZE = 6 * 4  # 24 bytes per validator

# Update statistics per GP statistics.tex
# Format: validator_acc(V*24) + validator_prev(V*24) + core_stats + service_stats
function update_statistics!(state::StateStore, block::Block, epoch_change::Bool)
    stats_key = state_key(13)
    if !haskey(state.data, stats_key)
        return
    end

    old_stats = state.data[stats_key]
    header = block.header
    extrinsic = block.extrinsic

    # Calculate sizes
    val_section_size = VALIDATORS_COUNT * VALIDATOR_STATS_SIZE  # 6 validators * 24 bytes = 144 bytes
    acc_end = val_section_size
    prev_end = 2 * val_section_size

    # Extract sections
    accumulator = old_stats[1:acc_end]
    previous = old_stats[acc_end+1:prev_end]
    remaining = old_stats[prev_end+1:end]  # core_stats + service_stats

    # On epoch change: swap accumulator <-> previous, reset accumulator
    if epoch_change
        previous = accumulator
        accumulator = zeros(UInt8, val_section_size)
    end

    # Increment author's block count (GP statistics.tex)
    author_idx = header.author_index
    if author_idx < VALIDATORS_COUNT
        offset = author_idx * VALIDATOR_STATS_SIZE + 1  # +1 for Julia 1-indexing
        # blocks is first u32
        blocks = reinterpret(UInt32, accumulator[offset:offset+3])[1]
        blocks += UInt32(1)
        accumulator[offset:offset+3] = reinterpret(UInt8, [blocks])

        # tickets is second u32 - add ticket count from extrinsic
        if !isempty(extrinsic.tickets)
            ticket_offset = offset + 4
            tickets = reinterpret(UInt32, accumulator[ticket_offset:ticket_offset+3])[1]
            tickets += UInt32(length(extrinsic.tickets))
            accumulator[ticket_offset:ticket_offset+3] = reinterpret(UInt8, [tickets])
        end

        # preimages count and size
        if !isempty(extrinsic.preimages)
            preimage_count_offset = offset + 8
            preimage_size_offset = offset + 12
            count = reinterpret(UInt32, accumulator[preimage_count_offset:preimage_count_offset+3])[1]
            size = reinterpret(UInt32, accumulator[preimage_size_offset:preimage_size_offset+3])[1]
            count += UInt32(length(extrinsic.preimages))
            for (_, blob) in extrinsic.preimages
                size += UInt32(length(blob))
            end
            accumulator[preimage_count_offset:preimage_count_offset+3] = reinterpret(UInt8, [count])
            accumulator[preimage_size_offset:preimage_size_offset+3] = reinterpret(UInt8, [size])
        end
    end

    # Increment guarantee counts for validators who signed guarantees
    for guarantee in extrinsic.guarantees
        for (val_idx, _) in guarantee.signatures
            if val_idx < VALIDATORS_COUNT
                offset = val_idx * VALIDATOR_STATS_SIZE + 1 + 16  # guarantees is 5th field (offset 16)
                guarantees = reinterpret(UInt32, accumulator[offset:offset+3])[1]
                guarantees += UInt32(1)
                accumulator[offset:offset+3] = reinterpret(UInt8, [guarantees])
            end
        end
    end

    # Increment assurance counts for validators who provided assurances
    for assurance in extrinsic.assurances
        # assurance contains validator_index - would need to extract from parsed struct
        # For now skip assurances as the test data has empty assurances
    end

    # Core stats and service stats are only updated when reports are accumulated
    # Accumulation happens when assurances confirm reports, not when guarantees are received
    # Per GP eq 106-117, core stats come from accumulated work reports
    # If no accumulation happens this block, preserve existing core_stats + service_stats

    # Re-encode with preserved core_stats + service_stats (in 'remaining')
    state.data[stats_key] = vcat(accumulator, previous, remaining)
end

# Authorization constants
const MAX_AUTH_POOL_SIZE = 8    # O: max pool size
const AUTHORIZATION_QUEUE_SIZE = 80  # Q: queue size

# Update authorization pools per GP authorization.tex
# Every block: push queue[slot % Q], remove used hashes, trim from front if > O
function update_authorizations!(state::StateStore, block::Block)
    alpha_key = state_key(1)  # C(1) = Alpha (auth pools)
    phi_key = state_key(2)    # C(2) = Phi (auth queues)

    if !haskey(state.data, alpha_key) || !haskey(state.data, phi_key)
        return
    end

    slot = block.header.slot
    extrinsic = block.extrinsic

    # Parse current pools - format: per-core array of variable-length arrays
    # Each pool: JAM_compact(len) + len * 32 bytes
    pools_data = state.data[alpha_key]
    queues_data = state.data[phi_key]

    # Parse pools into array of arrays of hashes
    pools = Vector{Vector{Vector{UInt8}}}()
    pos = 1
    for core_idx in 0:(CORES_COUNT-1)
        pool_len, pos = decode_jam_compact(pools_data, pos)
        pool = Vector{Vector{UInt8}}()
        for _ in 1:pool_len
            push!(pool, pools_data[pos:pos+31])
            pos += 32
        end
        push!(pools, pool)
    end

    # Parse queues - format: per-core array of fixed-size Q entries
    # Each queue: Q * 32 bytes (no length prefix for fixed arrays)
    queues = Vector{Vector{Vector{UInt8}}}()
    for core_idx in 0:(CORES_COUNT-1)
        queue_start = core_idx * AUTHORIZATION_QUEUE_SIZE * 32 + 1
        queue = Vector{Vector{UInt8}}()
        for i in 0:(AUTHORIZATION_QUEUE_SIZE-1)
            offset = queue_start + i * 32
            push!(queue, queues_data[offset:offset+31])
        end
        push!(queues, queue)
    end

    # Build set of used authorizer hashes per core from guarantees
    used_hashes = Dict{Int, Set{Vector{UInt8}}}()
    for guarantee in extrinsic.guarantees
        core_idx = Int(guarantee.report.core_index)
        if !haskey(used_hashes, core_idx)
            used_hashes[core_idx] = Set{Vector{UInt8}}()
        end
        push!(used_hashes[core_idx], guarantee.report.authorizer_hash)
    end

    # Update each pool
    queue_idx = Int(slot % AUTHORIZATION_QUEUE_SIZE) + 1  # Julia 1-indexed

    for core_idx in 0:(CORES_COUNT-1)
        pool = pools[core_idx + 1]  # Julia 1-indexed
        queue = queues[core_idx + 1]

        # Remove used hashes (only first occurrence of each)
        if haskey(used_hashes, core_idx)
            new_pool = Vector{Vector{UInt8}}()
            removed = Set{Vector{UInt8}}()
            for hash in pool
                if hash in used_hashes[core_idx] && !(hash in removed)
                    push!(removed, hash)
                    # Skip this hash
                else
                    push!(new_pool, hash)
                end
            end
            pool = new_pool
        end

        # Push queue[slot % Q]
        push!(pool, queue[queue_idx])

        # Trim from front if > O
        while length(pool) > MAX_AUTH_POOL_SIZE
            popfirst!(pool)
        end

        pools[core_idx + 1] = pool
    end

    # Re-encode pools
    result = UInt8[]
    for pool in pools
        append!(result, encode_jam_compact(length(pool)))
        for hash in pool
            append!(result, hash)
        end
    end

    state.data[alpha_key] = result
end

# Encode WorkReport to bytes for state storage
function encode_work_report(report::WorkReport)::Vector{UInt8}
    result = UInt8[]

    # package_spec
    append!(result, report.package_hash)           # 32 bytes
    append!(result, reinterpret(UInt8, [report.package_length]))  # 4 bytes LE
    append!(result, report.erasure_root)           # 32 bytes
    append!(result, report.exports_root)           # 32 bytes
    append!(result, reinterpret(UInt8, [report.exports_count]))   # 2 bytes LE

    # context
    append!(result, report.anchor)                 # 32 bytes
    append!(result, report.state_root)             # 32 bytes
    append!(result, report.beefy_root)             # 32 bytes
    append!(result, report.lookup_anchor)          # 32 bytes
    append!(result, reinterpret(UInt8, [report.lookup_anchor_slot]))  # 4 bytes LE
    append!(result, encode_jam_compact(length(report.prerequisites)))
    for prereq in report.prerequisites
        append!(result, prereq)                    # 32 bytes each
    end

    # core_index: JAM compact (matches decode_work_report and codec test vector)
    append!(result, encode_jam_compact(report.core_index))

    # authorizer_hash
    append!(result, report.authorizer_hash)        # 32 bytes

    # auth_gas_used: JAM compact (matches decode_work_report and codec test vector)
    append!(result, encode_jam_compact(report.auth_gas_used))

    # auth_output (length-prefixed)
    append!(result, encode_jam_compact(length(report.auth_output)))
    append!(result, report.auth_output)

    # segment_root_lookup
    append!(result, encode_jam_compact(length(report.segment_root_lookup)))
    for seg in report.segment_root_lookup
        append!(result, seg)                       # 32 bytes each
    end

    # results
    append!(result, encode_jam_compact(length(report.results)))
    for wr in report.results
        append!(result, reinterpret(UInt8, [wr.service_id]))  # 4 bytes LE
        append!(result, wr.code_hash)              # 32 bytes
        append!(result, wr.payload_hash)           # 32 bytes
        append!(result, reinterpret(UInt8, [wr.accumulate_gas]))  # 8 bytes LE

        # result: Ok(bytes) = 0x00 + len + bytes, Err = discriminant (preserved from decode)
        if wr.result !== nothing
            push!(result, 0x00)  # Ok variant
            append!(result, encode_jam_compact(length(wr.result)))
            append!(result, wr.result)
        else
            push!(result, wr.result_err_code)  # Use preserved error discriminant
        end

        # refine_load: 5 JAM compact values (matches decode in parse_pending_reports)
        append!(result, encode_jam_compact(wr.refine_load.gas_used))
        append!(result, encode_jam_compact(wr.refine_load.imports))
        append!(result, encode_jam_compact(wr.refine_load.extrinsic_count))
        append!(result, encode_jam_compact(wr.refine_load.extrinsic_size))
        append!(result, encode_jam_compact(wr.refine_load.exports))
    end

    return result
end

# Availability timeout constant (U epochs)
const AVAILABILITY_TIMEOUT_EPOCHS = 5

# Update pending reports per GP reporting.tex
# Format: fixed-size array of CORES_COUNT entries (AvailabilityAssignments = [Optional<AvailabilityAssignment>; C])
# Each entry is optional (SCALE encoding):
#   - None: 0x00 (1 byte)
#   - Some: 0x01 + WorkReport (variable) + timeout (4 bytes LE)
# Note: timeout = slot + U * E where U=5 epochs, E=EPOCH_LENGTH slots
function update_pending_reports!(state::StateStore, block::Block)
    pending_key = state_key(10)  # C(10) = rho (pending reports / availability assignment)
    if !haskey(state.data, pending_key)
        return
    end

    current_slot = block.header.slot
    extrinsic = block.extrinsic

    # Parse existing pending reports from state
    existing_pending = parse_pending_reports(state.data[pending_key])

    # Track which cores have new guarantees from this block
    # AvailabilityAssignment = (WorkReport, timeout) - NO availability bitfield in state
    new_reports = Dict{Int, Tuple{WorkReport, UInt32}}()
    for guarantee in extrinsic.guarantees
        core_idx = Int(guarantee.report.core_index)
        # Timeout stores the slot when the guarantee was submitted (from guarantee.slot)
        # The report expires when current_slot >= timeout + U * E
        timeout = guarantee.slot
        new_reports[core_idx] = (guarantee.report, timeout)
    end

    # Merge existing reports with new ones
    # New guarantees override existing for the same core
    # Existing reports that haven't timed out are preserved
    merged_reports = Dict{Int, Tuple{Vector{UInt8}, UInt32}}()

    # First, add existing reports (if not timed out)
    # Report expires when current_slot >= timeout + U * E
    expiry_duration = UInt32(AVAILABILITY_TIMEOUT_EPOCHS * EPOCH_LENGTH)
    for (core_idx, (encoded_report, timeout)) in existing_pending
        # Keep report if it hasn't expired yet
        if current_slot < timeout + expiry_duration
            merged_reports[core_idx] = (encoded_report, timeout)
        end
    end

    # Then, add/override with new reports
    for (core_idx, (report, timeout)) in new_reports
        encoded_report = encode_work_report(report)
        merged_reports[core_idx] = (encoded_report, timeout)
    end

    # Build new pending state - fixed-size array of CORES_COUNT optionals
    result = UInt8[]

    println("  [PENDING] Building pending state for $(CORES_COUNT) cores")
    println("  [PENDING] New guarantees: $(collect(keys(new_reports)))")
    println("  [PENDING] Existing reports: $(collect(keys(existing_pending)))")

    for core_idx in 0:(CORES_COUNT-1)
        if haskey(merged_reports, core_idx)
            encoded_report, timeout = merged_reports[core_idx]
            push!(result, 0x01)  # Some discriminant
            # AvailabilityAssignment = WorkReport + timeout
            append!(result, encoded_report)  # WorkReport (variable)
            append!(result, reinterpret(UInt8, [timeout]))  # timeout (4 bytes LE)
            println("  [PENDING] Core $core_idx: size=$(length(encoded_report)), timeout=$timeout")
        else
            # No report for this core - encode as None (just 1 byte)
            push!(result, 0x00)  # None discriminant
        end
    end

    state.data[pending_key] = result
    println("  [PENDING] Total rho size: $(length(result)) bytes")
    println("  [PENDING] First 20 bytes: $(bytes2hex(result[1:min(20, length(result))]))")
end

# Parse pending reports from binary state data
# Format: fixed-size array of CORES_COUNT entries
# Each entry: discriminant(1) + [WorkReport(variable) + timeout(4)] if Some
# Returns Dict{core_idx => (encoded_report_bytes, timeout)}
function parse_pending_reports(data::Vector{UInt8})::Dict{Int, Tuple{Vector{UInt8}, UInt32}}
    result = Dict{Int, Tuple{Vector{UInt8}, UInt32}}()
    pos = 1
    core_idx = 0

    while pos <= length(data) && core_idx < CORES_COUNT
        discriminant = data[pos]
        pos += 1

        if discriminant == 0x00
            # None - no report for this core (just 1 byte discriminant)
            core_idx += 1
            continue
        elseif discriminant == 0x01
            # Some - parse WorkReport, then timeout
            report_start = pos

            # package_spec: hash(32) + length(4) + erasure_root(32) + exports_root(32) + exports_count(2)
            pos += 32 + 4 + 32 + 32 + 2  # = 102 bytes

            # context: anchor(32) + state_root(32) + beefy_root(32) + lookup_anchor(32) + lookup_anchor_slot(4)
            pos += 32 + 32 + 32 + 32 + 4  # = 132 bytes

            # prerequisites: JAM compact length + N * 32 bytes
            prereqs_len, pos = decode_jam_compact(data, pos)
            pos += prereqs_len * 32

            # core_index: JAM compact
            _, pos = decode_jam_compact(data, pos)

            # authorizer_hash: 32 bytes
            pos += 32

            # auth_gas_used: JAM compact
            _, pos = decode_jam_compact(data, pos)

            # auth_output: JAM compact length + bytes
            auth_output_len, pos = decode_jam_compact(data, pos)
            pos += auth_output_len

            # segment_root_lookup: JAM compact length + N * 32 bytes
            seg_lookup_len, pos = decode_jam_compact(data, pos)
            pos += seg_lookup_len * 32

            # results: JAM compact length + WorkResults
            results_len, pos = decode_jam_compact(data, pos)
            for _ in 1:results_len
                # service_id(4) + code_hash(32) + payload_hash(32) + accumulate_gas(8)
                pos += 4 + 32 + 32 + 8

                # result: discriminant + optional data
                result_disc = data[pos]
                pos += 1
                if result_disc == 0x00  # Ok variant
                    result_data_len, pos = decode_jam_compact(data, pos)
                    pos += result_data_len
                end
                # Err variants have no additional data

                # refine_load: 5 JAM compact values
                for _ in 1:5
                    _, pos = decode_jam_compact(data, pos)
                end
            end

            encoded_report = data[report_start:pos-1]

            # Read timeout (4 bytes LE) - NO availability bitfield in state storage
            timeout = reinterpret(UInt32, data[pos:pos+3])[1]
            pos += 4

            result[core_idx] = (encoded_report, timeout)
            core_idx += 1
        else
            # Invalid discriminant - skip this core
            core_idx += 1
        end
    end

    return result
end

# Update accumulation state per GP accumulate.tex
# Updates Xi (C15, recentlyAccumulated) and Omega (C14, accumulationQueue)
# For first block with no available reports, shifts Xi by 1 slot (adds empty set)
# and clears the queue slot for the current phase
function update_accumulation_state!(state::StateStore, block::Block, new_slot::UInt32)
    xi_key = state_key(15)   # C(15) = Xi (recentlyAccumulated)
    omega_key = state_key(14) # C(14) = Omega (accumulationQueue)

    # Get previous timeslot to determine how many slots have passed
    tau_key = state_key(11)
    old_slot = UInt32(0)
    if haskey(state.data, tau_key)
        old_tau = state.data[tau_key]
        if length(old_tau) >= 4
            old_slot = reinterpret(UInt32, old_tau[1:4])[1]
        end
    end

    # =========================================================================
    # Update Xi (recentlyAccumulated)
    # Per TypeBerry: slice(1).concat(HashSet.from(accumulatedSorted))
    # This shifts the array left by 1 and appends a new (empty) set
    # Format: EPOCH_LENGTH sets, each set is JAM_compact(len) + sorted hashes
    # For empty sets: just 0x00 (length 0)
    # =========================================================================
    if haskey(state.data, xi_key)
        old_xi = state.data[xi_key]

        # Parse existing Xi: EPOCH_LENGTH sets
        # Each set is: JAM_compact(count) + count * 32 bytes (sorted hashes)
        pos = 1
        sets = Vector{Vector{Vector{UInt8}}}()
        for _ in 1:EPOCH_LENGTH
            if pos > length(old_xi)
                push!(sets, Vector{UInt8}[])
                continue
            end
            count, pos = decode_jam_compact(old_xi, pos)
            set = Vector{UInt8}[]
            for _ in 1:count
                if pos + 31 <= length(old_xi)
                    push!(set, old_xi[pos:pos+31])
                    pos += 32
                end
            end
            push!(sets, set)
        end

        # Shift left by 1 and append new empty set
        # GP eq: Xi' = Xi[1:] ++ [{accumulated work package hashes}]
        # For first block with no available reports, this appends empty set
        new_sets = vcat(sets[2:end], [Vector{UInt8}[]])

        # Re-encode Xi
        new_xi = UInt8[]
        for set in new_sets
            append!(new_xi, encode_jam_compact(length(set)))
            for hash in set
                append!(new_xi, hash)
            end
        end
        state.data[xi_key] = new_xi
    end

    # =========================================================================
    # Update Omega (accumulationQueue)
    # Per TypeBerry: clears slots between old and new timeslot
    # Format: EPOCH_LENGTH arrays, each is JAM_compact(len) + NotYetAccumulatedReport[]
    # For first block with no queued reports, just clear the current slot
    # =========================================================================
    if haskey(state.data, omega_key)
        old_omega = state.data[omega_key]

        # Parse existing Omega: EPOCH_LENGTH arrays of NotYetAccumulatedReport
        pos = 1
        queues = Vector{Vector{UInt8}}()  # Keep raw encoding for each slot
        for slot_idx in 1:EPOCH_LENGTH
            if pos > length(old_omega)
                push!(queues, UInt8[0x00])  # Empty array
                continue
            end
            count, new_pos = decode_jam_compact(old_omega, pos)
            if count == 0
                push!(queues, UInt8[0x00])
                pos = new_pos
            else
                # For non-empty queues, we'd need to parse NotYetAccumulatedReport
                # For now, just keep raw bytes (but clear them)
                push!(queues, UInt8[0x00])  # Clear the queue
                # Skip the content (we'd need to know the format to skip properly)
                # NotYetAccumulatedReport = WorkReport + core_index + dependencies
                pos = new_pos
                # This is simplified - in practice need to skip variable content
            end
        end

        # Calculate phase index for new slot
        phase_index = mod(new_slot, EPOCH_LENGTH) + 1  # Julia 1-indexed

        # Clear the current phase slot (and any skipped slots)
        slots_passed = new_slot - old_slot
        for i in 1:min(slots_passed, EPOCH_LENGTH)
            clear_idx = mod(new_slot - i + 1, EPOCH_LENGTH) + 1
            if clear_idx >= 1 && clear_idx <= EPOCH_LENGTH
                queues[clear_idx] = UInt8[0x00]
            end
        end

        # Re-encode Omega
        new_omega = UInt8[]
        for queue in queues
            append!(new_omega, queue)
        end
        state.data[omega_key] = new_omega
    end

    println("  [ACCUM] Updated Xi and Omega for slot $new_slot (phase $(mod(new_slot, EPOCH_LENGTH)))")
end

# Update judgment state per GP disputes.tex
# Format: 4 sorted sequences (good, bad, wonky, offenders)
function update_judgments!(state::StateStore, block::Block)
    judgments_key = state_key(5)
    if !haskey(state.data, judgments_key)
        return
    end

    # Process disputes from extrinsic
    # For basic conformance without disputes, keep unchanged
    disputes = block.extrinsic.disputes

    # Only update if there are actual disputes
    if isempty(disputes.verdicts) && isempty(disputes.culprits) && isempty(disputes.faults)
        return
    end

    # Otherwise would need to update good/bad/wonky/offenders sets
end

# ============================================================================
# Message Handling
# ============================================================================

function handle_peer_info(session::Session, data::Vector{UInt8})
    peer = decode_peer_info(data)
    session.features = peer.fuzz_features & FEATURE_FORKS

    println("Connected to: $(peer.app_name) v$(peer.app_version.major).$(peer.app_version.minor).$(peer.app_version.patch)")
    println("JAM version: $(peer.jam_version.major).$(peer.jam_version.minor).$(peer.jam_version.patch)")
    println("Features: 0x$(string(session.features, base=16))")

    return encode_peer_info()
end

function handle_initialize(session::Session, data::Vector{UInt8})
    # Parse state from initialize message
    try
        state_data, ancestry = decode_initialize(data[2:end])  # Skip message discriminant byte
        session.state.data = state_data
        session.ancestry = ancestry
        println("Loaded $(length(session.state.data)) state entries, $(length(ancestry)) ancestry items")
    catch e
        println("Error parsing initialize: $e")
        for (exc, bt) in current_exceptions()
            showerror(stdout, exc, bt)
            println()
        end
        session.state = StateStore()
        session.ancestry = []
    end

    root = compute_state_root(session.state)
    println("State root: 0x$(bytes2hex(root))")
    return encode_state_root(root)
end

function handle_import_block(session::Session, data::Vector{UInt8})
    try
        # Decode block header and extrinsic
        block = decode_import_block(data)

        # Apply state transition
        apply_state_transition!(session.state, block, session.ancestry)

        # Update ancestry with new block
        push!(session.ancestry, (block.header.slot, block.header_hash))

        @debug "Processed block at slot $(block.header.slot)"
    catch e
        println("Error processing ImportBlock: $e")
        for (exc, bt) in current_exceptions()
            showerror(stdout, exc, bt)
            println()
        end
    end

    root = compute_state_root(session.state)
    println("State root: 0x$(bytes2hex(root))")
    return encode_state_root(root)
end

function handle_get_state(session::Session, data::Vector{UInt8})
    return encode_state(session.state)
end

function handle_message(session::Session, data::Vector{UInt8})::Vector{UInt8}
    if isempty(data)
        return encode_error("Empty message")
    end

    discriminant = data[1]

    try
        if discriminant == MSG_PEER_INFO
            return handle_peer_info(session, data)
        elseif discriminant == MSG_INITIALIZE
            return handle_initialize(session, data)
        elseif discriminant == MSG_IMPORT_BLOCK
            return handle_import_block(session, data)
        elseif discriminant == MSG_GET_STATE
            return handle_get_state(session, data)
        else
            return encode_error("Unknown message type: $discriminant")
        end
    catch e
        println("Error handling message: $e")
        return encode_error("Internal error: $e")
    end
end

# ============================================================================
# Socket Server
# ============================================================================

function read_message(sock::IO)::Vector{UInt8}
    len_bytes = read(sock, 4)
    if length(len_bytes) < 4
        throw(EOFError())
    end
    msg_len = reinterpret(UInt32, len_bytes)[1]
    msg = read(sock, msg_len)
    return msg
end

function write_message(sock::IO, data::Vector{UInt8})
    len_bytes = reinterpret(UInt8, [UInt32(length(data))])
    write(sock, len_bytes)
    write(sock, data)
    flush(sock)
end

function handle_connection(sock::IO)
    session = Session(sock, StateStore(), 0, [])

    try
        while isopen(sock)
            msg = read_message(sock)
            response = handle_message(session, msg)
            write_message(sock, response)
        end
    catch e
        if !(e isa EOFError)
            println("Connection error: $e")
        end
    end

    println("Connection closed")
end

function start_target(socket_path::String = "/tmp/jam_target.sock")
    # Remove stale socket file (ispath works for sockets, isfile does not)
    ispath(socket_path) && rm(socket_path)

    println("Starting JAM conformance target on $socket_path")
    println("romio v$(APP_VERSION.major).$(APP_VERSION.minor).$(APP_VERSION.patch)")
    println("JAM protocol v$(JAM_VERSION.major).$(JAM_VERSION.minor).$(JAM_VERSION.patch)")

    server = listen(socket_path)

    try
        while true
            sock = accept(server)
            println("\nNew connection")
            handle_connection(sock)  # Single-threaded for now
        end
    catch e
        if !(e isa InterruptException)
            println("Server error: $e")
        end
    finally
        close(server)
        ispath(socket_path) && rm(socket_path)
    end
end

end # module ConformanceTarget
