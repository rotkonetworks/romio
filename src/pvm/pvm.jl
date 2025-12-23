# complete pvm interpreter implementation following graypaper spec
module PVM

# No external dependencies - using native Julia arrays

# Debug configuration
include("debug.jl")
using .PVMDebug

# Include host call interface
include("host_calls.jl")
using .HostCalls

# constants
const PAGE_SIZE = 4096  # 2^12 bytes
const ZONE_SIZE = 65536  # 2^16 bytes
const MAX_INPUT = 16777216  # 2^24 bytes
const DYNAM_ALIGN = 2  # dynamic address alignment

# Helper function: round up to next page boundary
@inline function P_func(addr::UInt32)::UInt32
    page_mask = UInt32(PAGE_SIZE - 1)
    return (addr + page_mask) & ~page_mask
end

# exit reasons - using UInt8 for fast comparison
const CONTINUE = UInt8(0)
const HALT = UInt8(1)
const PANIC = UInt8(2)
const OOG = UInt8(3)
const FAULT = UInt8(4)
const HOST = UInt8(5)

# Status type alias for documentation
const Status = UInt8

# memory access permissions
const READ = :R
const WRITE = :W
const NONE = nothing

# Flat memory design for fast access - uses contiguous arrays for known regions
# PolkaVM memory layout:
#   0x00000000 - 0x0000FFFF: Inaccessible (first 64KB)
#   0x00010000 - RO region: Read-only data
#   RW region: Read-write data
#   Stack region near 0xFFFE0000: Stack (grows down)
#   Heap: Dynamic (via sbrk)

const PAGE_BITS = 12  # 4KB pages (must match PAGE_SIZE = 4096)
const PAGE_MASK = UInt32((1 << PAGE_BITS) - 1)

# Memory region with flat array storage
# Uses concrete types only - no Union{Nothing, T} to avoid boxing
struct FlatRegion
    base::UInt32           # Start address (0 = disabled)
    limit::UInt32          # End address (exclusive) - avoids addition in hot path
    data::Vector{UInt8}    # Flat array - direct indexing!
    writable::Bool         # RO vs RW
end

# Empty sentinel region (never matches any address > 0)
const EMPTY_REGION = FlatRegion(UInt32(0), UInt32(0), UInt8[], false)

function FlatRegion(base::UInt32, size::UInt32, writable::Bool)
    FlatRegion(base, base + size, zeros(UInt8, size), writable)
end

# Check if address is in this region - single comparison using precomputed limit
@inline function in_region(r::FlatRegion, addr::UInt32)::Bool
    addr >= r.base && addr < r.limit
end

# Get byte from region (addr is absolute address)
@inline function region_read(r::FlatRegion, addr::UInt32)::UInt8
    @inbounds r.data[addr - r.base + 1]
end

# Set byte in region (addr is absolute address)
@inline function region_write!(r::FlatRegion, addr::UInt32, val::UInt8)
    @inbounds r.data[addr - r.base + 1] = val
end

# Sparse fallback for dynamic heap allocations
struct SparseMemory
    pages::Dict{UInt32, Vector{UInt8}}
    page_perms::Dict{UInt32, Bool}  # true = writable, false = readonly
end

SparseMemory() = SparseMemory(Dict{UInt32, Vector{UInt8}}(), Dict{UInt32, Bool}())

mutable struct Memory
    # Fast path: flat regions for known areas (stack/RO/RW)
    # Uses concrete FlatRegion type (no Union) - EMPTY_REGION as sentinel
    ro_region::FlatRegion
    rw_region::FlatRegion
    stack_region::FlatRegion

    # Slow path: sparse storage for heap and other dynamic areas
    sparse::SparseMemory

    # Heap management
    current_heap_pointer::UInt32
    heap_base::UInt32
    heap_limit::UInt32  # Max heap address before hitting stack

    function Memory()
        new(EMPTY_REGION, EMPTY_REGION, EMPTY_REGION, SparseMemory(), UInt32(0), UInt32(0), UInt32(0))
    end
end

# Initialize memory regions from program layout
function init_memory_regions!(mem::Memory, ro_base::UInt32, ro_size::UInt32, ro_data::Vector{UInt8},
                              rw_base::UInt32, rw_size::UInt32, rw_data::Vector{UInt8},
                              stack_low::UInt32, stack_high::UInt32,
                              heap_base::UInt32, heap_limit::UInt32)
    # RO region
    if ro_size > 0
        mem.ro_region = FlatRegion(ro_base, ro_size, false)
        for (i, b) in enumerate(ro_data)
            mem.ro_region.data[i] = b
        end
    end

    # RW region (includes BSS - already zeroed)
    if rw_size > 0
        mem.rw_region = FlatRegion(rw_base, rw_size, true)
        for (i, b) in enumerate(rw_data)
            mem.rw_region.data[i] = b
        end
    end

    # Stack region
    stack_size = stack_high - stack_low
    if stack_size > 0
        mem.stack_region = FlatRegion(stack_low, stack_size, true)
    end

    mem.current_heap_pointer = heap_base
    mem.heap_base = heap_base
    mem.heap_limit = heap_limit
end

# Legacy sparse memory interface (for compatibility with existing code)
# These are only used for dynamic heap allocations now

@inline function get_sparse_page!(m::SparseMemory, page_num::UInt32)::Vector{UInt8}
    page = get(m.pages, page_num, nothing)
    if page === nothing
        page = zeros(UInt8, PAGE_SIZE)
        m.pages[page_num] = page
        m.page_perms[page_num] = true  # Heap pages are writable
    end
    return page
end

@inline function sparse_read(m::SparseMemory, addr::UInt32)::UInt8
    page_num = addr >> PAGE_BITS
    offset = (addr & PAGE_MASK) + 1
    page = get(m.pages, page_num, nothing)
    if page === nothing
        return UInt8(0)
    end
    @inbounds return page[offset]
end

@inline function sparse_write!(m::SparseMemory, addr::UInt32, val::UInt8)
    page_num = addr >> PAGE_BITS
    offset = (addr & PAGE_MASK) + 1
    page = get_sparse_page!(m, page_num)
    @inbounds page[offset] = val
end

@inline function sparse_has_access(m::SparseMemory, addr::UInt32, write::Bool)::Bool
    page_num = addr >> PAGE_BITS
    perm = get(m.page_perms, page_num, nothing)
    if perm === nothing
        return false
    end
    return !write || perm  # Read always OK if page exists, write only if writable
end

# Legacy compatibility interface for graypaper setup_memory!
# This wraps the flat regions with a Dict-like interface for existing code

struct MemoryDataWrapper
    mem::Memory
end

# Length for compatibility with code that checks bounds
Base.length(w::MemoryDataWrapper) = typemax(UInt32)

# copyto! for bulk memory operations
function Base.copyto!(w::MemoryDataWrapper, dest_offset::Integer, src::Vector{UInt8}, src_offset::Integer, n::Integer)
    for i in 0:n-1
        w[dest_offset + i] = src[src_offset + i]
    end
    return w
end

# Range indexing for slicing
function Base.getindex(w::MemoryDataWrapper, r::UnitRange{<:Integer})
    return [w[i] for i in r]
end

@inline function Base.getindex(w::MemoryDataWrapper, addr::Integer)::UInt8
    addr32 = UInt32(addr - 1)  # Convert 1-indexed to 0-indexed
    mem = w.mem

    # Check flat regions
    ro = mem.ro_region
    if addr32 >= ro.base && addr32 < ro.limit
        return ro.data[addr32 - ro.base + 1]
    end

    rw = mem.rw_region
    if addr32 >= rw.base && addr32 < rw.limit
        return rw.data[addr32 - rw.base + 1]
    end

    stack = mem.stack_region
    if addr32 >= stack.base && addr32 < stack.limit
        return stack.data[addr32 - stack.base + 1]
    end

    # Fallback to sparse
    return sparse_read(mem.sparse, addr32)
end

@inline function Base.setindex!(w::MemoryDataWrapper, val::UInt8, addr::Integer)
    addr32 = UInt32(addr - 1)  # Convert 1-indexed to 0-indexed
    mem = w.mem

    # Check flat regions
    rw = mem.rw_region
    if addr32 >= rw.base && addr32 < rw.limit
        rw.data[addr32 - rw.base + 1] = val
        return val
    end

    stack = mem.stack_region
    if addr32 >= stack.base && addr32 < stack.limit
        stack.data[addr32 - stack.base + 1] = val
        return val
    end

    # Fallback to sparse (heap, input areas, etc.)
    sparse_write!(mem.sparse, addr32, val)
    return val
end

struct MemoryAccessWrapper
    mem::Memory
end

@inline function Base.getindex(w::MemoryAccessWrapper, page_idx::Integer)::Union{Symbol, Nothing}
    page_addr = UInt32((page_idx - 1) * PAGE_SIZE)
    mem = w.mem

    # Check flat regions
    ro = mem.ro_region
    if page_addr >= ro.base && page_addr < ro.limit
        return READ
    end

    rw = mem.rw_region
    if page_addr >= rw.base && page_addr < rw.limit
        return WRITE
    end

    stack = mem.stack_region
    if page_addr >= stack.base && page_addr < stack.limit
        return WRITE
    end

    # Check sparse pages
    perm = get(mem.sparse.page_perms, UInt32(page_idx - 1), nothing)
    if perm !== nothing
        return perm ? WRITE : READ
    end

    return nothing
end

@inline function Base.setindex!(w::MemoryAccessWrapper, val::Union{Symbol, Nothing}, page_idx::Integer)
    # For graypaper setup - store in sparse
    if val === nothing
        delete!(w.mem.sparse.page_perms, UInt32(page_idx - 1))
    else
        w.mem.sparse.page_perms[UInt32(page_idx - 1)] = (val == WRITE)
    end
    return val
end

@inline function Base.get(w::MemoryAccessWrapper, page_idx::Integer, default)
    result = w[page_idx]
    return result === nothing ? default : result
end

@inline Base.length(w::MemoryAccessWrapper) = 1048576  # 1M pages = 4GB

# Property accessors for Memory to provide legacy interface
Base.getproperty(m::Memory, s::Symbol) = begin
    if s === :data
        return MemoryDataWrapper(m)
    elseif s === :access
        return MemoryAccessWrapper(m)
    else
        return getfield(m, s)
    end
end

# Inner PVM guest machine state
mutable struct GuestPVM
    code::Vector{UInt8}  # program blob
    ram::Memory  # guest memory (separate from parent)
    pc::UInt32  # guest program counter
end

mutable struct PVMState
    # HOT PATH - Accessed every instruction (L1 cache line ~64 bytes)
    pc::UInt32  # program counter (4 bytes)
    status::UInt8  # execution status (1 byte) - CONTINUE/HALT/PANIC/OOG/FAULT/HOST
    gas::Int64  # gas remaining (8 bytes)
    instructions::Vector{UInt8}  # instruction bytes (24 bytes ptr+len+cap)
    opcode_mask::BitVector  # marks opcode positions (24 bytes)
    skip_distances::Vector{UInt8}  # precomputed skip distances for each position
    # = 92 bytes (~1.5 cache lines)

    # FREQUENTLY ACCESSED - Registers and memory (next cache line)
    registers::Vector{UInt64}  # 13 general purpose registers (24 bytes)
    memory::Memory  # (8 bytes ptr)

    # LESS FREQUENTLY ACCESSED - Jump table and special features
    jump_table::Vector{UInt32}  # dynamic jump targets
    host_call_id::UInt32  # temporary storage for host call ID
    exports::Vector{Vector{UInt8}}  # list of exported memory segments
    machines::Dict{UInt32, GuestPVM}  # machine_id => guest PVM
end

# Precompute skip distances from opcode mask
function precompute_skip_distances(mask::BitVector)::Vector{UInt8}
    n = length(mask)
    distances = zeros(UInt8, n)
    for i in 1:n
        if mask[i]  # Only compute for opcode positions
            for j in 1:min(24, n-i)
                if mask[i + j]
                    distances[i] = UInt8(j - 1)
                    @goto found
                end
            end
            distances[i] = UInt8(min(24, n - i))
            @label found
        end
    end
    return distances
end

# Read graypaper varint from bytes
# Graypaper encoding: see serialization section
function read_varint(data::Vector{UInt8}, offset::Int)::Tuple{UInt64, Int}
    if offset > length(data)
        return (UInt64(0), offset)
    end

    first_byte = data[offset]

    # Case 1: x = 0
    if first_byte == 0
        return (UInt64(0), offset + 1)
    end

    # Case 2: x < 128 (l=0, direct encoding for values < 2^7)
    # For l=0: 2^7*0 <= x < 2^7*1, so 0 <= x < 128
    # First byte range: [2^8 - 2^8, 2^8 - 2^7) = [0, 128)
    if first_byte < 128
        return (UInt64(first_byte), offset + 1)
    end

    # Determine l from first byte
    # l=1: [128, 192) -> 2^7 <= x < 2^14
    # l=2: [192, 224) -> 2^14 <= x < 2^21
    # l=3: [224, 240) -> 2^21 <= x < 2^28
    # l=4: [240, 248) -> 2^28 <= x < 2^35
    # l=5: [248, 252) -> 2^35 <= x < 2^42
    # l=6: [252, 254) -> 2^42 <= x < 2^49
    # l=7: [254, 255) -> 2^49 <= x < 2^56
    # l=8: [255, 256) -> 2^56 <= x < 2^64

    l = if first_byte < 192
        1
    elseif first_byte < 224
        2
    elseif first_byte < 240
        3
    elseif first_byte < 248
        4
    elseif first_byte < 252
        5
    elseif first_byte < 254
        6
    elseif first_byte < 255
        7
    else  # first_byte == 255
        8
    end

    if offset + l > length(data)
        return (UInt64(0), offset)
    end

    # Extract header value
    # header_val = first_byte - (2^8 - 2^(8-l))
    header_offset = UInt64(256 - (1 << (8 - l)))
    header_val = UInt64(first_byte) - header_offset

    # Read next l bytes as little-endian
    remainder = UInt64(0)
    for i in 0:l-1
        remainder |= UInt64(data[offset + 1 + i]) << (8 * i)
    end

    # Reconstruct: header_val * 2^(8l) + remainder
    result = (header_val << (8 * l)) + remainder

    return (result, offset + 1 + l)
end

# Read fixed-length little-endian integer (graypaper encode[l])
function read_fixed_le(data::Vector{UInt8}, offset::Int, len::Int)::Tuple{UInt64, Int}
    if offset + len - 1 > length(data)
        return (UInt64(0), offset)
    end

    result = UInt64(0)
    for i in 0:len-1
        result |= UInt64(data[offset + i]) << (8 * i)
    end

    return (result, offset + len)
end

# decode program blob per graypaper spec (equation 764 + deblob)
# Format: E_3(len(o)) ++ E_3(len(w)) ++ E_2(z) ++ E_3(s) ++ o ++ w ++ E_4(len(c)) ++ c
# Then c = encode(len(j)) ++ encode[1](z) ++ encode(len(c)) ++ encode[z](j) ++ code ++ mask
function deblob(program::Vector{UInt8})
    if length(program) < 20
        return nothing
    end

    offset = 1

    # Skip metadata header if present (toplevel service blob format)
    # encode(var(m), c) = encode(len(m)) ++ m ++ c
    if program[1] < 0x80 && program[1] > 0 && length(program) > program[1]
        metadata_len = Int(program[1])
        offset = 1 + 1 + metadata_len  # Skip length byte + metadata
    end

    # Parse graypaper program blob format (equation 764)
    # E_3(len(o)) - RO data length (3 bytes, little-endian)
    ro_len, offset = read_fixed_le(program, offset, 3)

    # E_3(len(w)) - RW data length (3 bytes)
    rw_len, offset = read_fixed_le(program, offset, 3)

    # E_2(z) - stack pages (2 bytes)
    stack_pages, offset = read_fixed_le(program, offset, 2)

    # E_3(s) - stack bytes (3 bytes)
    stack_bytes, offset = read_fixed_le(program, offset, 3)

    # Extract o - RO data
    ro_data_start = offset
    ro_data_end = offset + Int(ro_len) - 1
    if ro_data_end > length(program)
        return nothing
    end
    ro_data = if ro_len > 0
        program[ro_data_start:ro_data_end]
    else
        UInt8[]
    end

    # Debug: check offset 0x900
    # if length(ro_data) > 0x900
    #     println("  [DEBLOB] ro_data[0x901] (offset 0x900) = 0x$(string(ro_data[0x901], base=16, pad=2))")
    # end

    offset = ro_data_end + 1

    # Extract w - RW data
    rw_data_start = offset
    rw_data_end = offset + Int(rw_len) - 1
    if rw_data_end > length(program)
        return nothing
    end
    rw_data = if rw_len > 0
        program[rw_data_start:rw_data_end]
    else
        UInt8[]
    end
    offset = rw_data_end + 1

    # E_4(len(c)) - code blob length (4 bytes)
    code_blob_len, offset = read_fixed_le(program, offset, 4)


    if offset + Int(code_blob_len) - 1 > length(program)
        return nothing
    end

    # Extract code blob c
    code_blob = program[offset:offset+Int(code_blob_len)-1]

    # Now deblob the code blob c
    # Format: encode(len(j)) ++ encode[1](z) ++ encode(len(c)) ++ encode[z](j) ++ code ++ mask
    c_offset = 1

    # Read jump table count (varint)
    jump_count, c_offset = read_varint(code_blob, c_offset)
    if c_offset > length(code_blob)
        return nothing
    end

    # Read jump entry size (1 byte)
    if c_offset > length(code_blob)
        return nothing
    end
    jump_size = code_blob[c_offset]
    c_offset += 1

    # Read code length (varint)
    code_len, c_offset = read_varint(code_blob, c_offset)
    if c_offset > length(code_blob)
        return nothing
    end

    # Read jump table
    jump_table = UInt32[]
    for _ in 1:jump_count
        if c_offset + jump_size > length(code_blob)
            return nothing
        end
        val = UInt32(0)
        for i in 0:jump_size-1
            val |= UInt32(code_blob[c_offset + i]) << (8*i)
        end
        push!(jump_table, val)
        c_offset += jump_size
    end


    # Read instructions
    if c_offset + Int(code_len) - 1 > length(code_blob)
        return nothing
    end
    instructions = code_blob[c_offset:c_offset+Int(code_len)-1]
    c_offset += Int(code_len)

    # Read opcode mask (bitstring encoded - 8 bits per byte)
    # Mask length in bytes: ceil(code_len / 8)
    mask_byte_len = div(Int(code_len) + 7, 8)

    if c_offset + mask_byte_len - 1 > length(code_blob)
        return nothing
    end

    mask_bytes = code_blob[c_offset:c_offset+mask_byte_len-1]

    # Decode bitstring: bits are packed LSB first in each byte
    opcode_mask = BitVector(undef, Int(code_len))
    for i in 0:Int(code_len)-1
        byte_idx = div(i, 8) + 1  # Julia 1-indexed
        bit_idx = i % 8
        opcode_mask[i+1] = (mask_bytes[byte_idx] & (1 << bit_idx)) != 0
    end

    return (instructions, opcode_mask, jump_table, ro_data, rw_data, Int(stack_pages), Int(stack_bytes))
end

# find next instruction (skip distance)
function skip_distance(mask::BitVector, pos::Int)
    for i in 1:min(24, length(mask)-pos)
        if pos + i <= length(mask) && mask[pos + i]
            return i - 1
        end
    end
    return min(24, length(mask) - pos)
end

# memory access helpers
# Fast memory access using flat regions - no Dict lookups, no Union types!
@inline function read_u8(state::PVMState, addr::UInt64)
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # First 64KB always inaccessible - return FAULT not PANIC
        # The first 64KB is unmapped but reading from it is a page fault, not a crash
        if addr32 < 0x10000
            state.status = FAULT
            return UInt8(0)
        end

        # Try RO region first (most common for code constants)
        # Using precomputed limit avoids addition in hot path
        ro = mem.ro_region
        if addr32 >= ro.base && addr32 < ro.limit
            return ro.data[addr32 - ro.base + 1]
        end

        # Try RW region (data section)
        rw = mem.rw_region
        if addr32 >= rw.base && addr32 < rw.limit
            return rw.data[addr32 - rw.base + 1]
        end

        # Try stack region
        stack = mem.stack_region
        if addr32 >= stack.base && addr32 < stack.limit
            return stack.data[addr32 - stack.base + 1]
        end

        # Fallback to sparse (heap and other dynamic areas like input)
        # Check if the address exists in sparse memory
        val = sparse_read(mem.sparse, addr32)
        if val != 0x00 || haskey(mem.sparse.pages, addr32 >> 12)
            return val
        end

        # No access
        state.status = FAULT
        state.gas -= 1
        return UInt8(0)
    end
end

@inline function write_u8(state::PVMState, addr::UInt64, val::UInt8)
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # First 64KB always inaccessible - return FAULT not PANIC
        if addr32 < 0x10000
            state.status = FAULT
            return
        end

        # Try RW region first (most writes go here)
        rw = mem.rw_region
        if addr32 >= rw.base && addr32 < rw.limit
            rw.data[addr32 - rw.base + 1] = val
            return
        end

        # Try stack region
        stack = mem.stack_region
        if addr32 >= stack.base && addr32 < stack.limit
            stack.data[addr32 - stack.base + 1] = val
            return
        end

        # Fallback to sparse (heap)
        if addr32 >= mem.heap_base && addr32 < mem.current_heap_pointer
            sparse_write!(mem.sparse, addr32, val)
            return
        end

        # RO region - not writable
        ro = mem.ro_region
        if addr32 >= ro.base && addr32 < ro.limit
            state.status = FAULT
            state.gas -= 1
            return
        end

        # No access
        state.status = FAULT
        state.gas -= 1
    end
end

# Optimized: Zero-allocation read for 32-bit values
# Direct word read from flat region using unsafe_load for maximum speed
@inline function region_read_u32(data::Vector{UInt8}, offset::Int)::UInt32
    GC.@preserve data begin
        ptr = pointer(data, offset)
        unsafe_load(Ptr{UInt32}(ptr))
    end
end

@inline function region_read_u64(data::Vector{UInt8}, offset::Int)::UInt64
    GC.@preserve data begin
        ptr = pointer(data, offset)
        unsafe_load(Ptr{UInt64}(ptr))
    end
end

@inline function read_u32_fast(state::PVMState, addr::UInt64)::UInt32
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # Single region check for entire word
        ro = mem.ro_region
        if addr32 >= ro.base && addr32 + 3 < ro.limit
            return region_read_u32(ro.data, Int(addr32 - ro.base + 1))
        end

        rw = mem.rw_region
        if addr32 >= rw.base && addr32 + 3 < rw.limit
            return region_read_u32(rw.data, Int(addr32 - rw.base + 1))
        end

        stack = mem.stack_region
        if addr32 >= stack.base && addr32 + 3 < stack.limit
            return region_read_u32(stack.data, Int(addr32 - stack.base + 1))
        end

        # Fallback to byte-by-byte for cross-region or sparse
        b0 = read_u8(state, addr)
        state.status != CONTINUE && return UInt32(0)
        b1 = read_u8(state, addr + 1)
        state.status != CONTINUE && return UInt32(0)
        b2 = read_u8(state, addr + 2)
        state.status != CONTINUE && return UInt32(0)
        b3 = read_u8(state, addr + 3)
        return UInt32(b0) | (UInt32(b1) << 8) | (UInt32(b2) << 16) | (UInt32(b3) << 24)
    end
end

# Direct word write to flat region using unsafe_store! for maximum speed
@inline function region_write_u32!(data::Vector{UInt8}, offset::Int, val::UInt32)
    GC.@preserve data begin
        ptr = pointer(data, offset)
        unsafe_store!(Ptr{UInt32}(ptr), val)
    end
end

@inline function region_write_u64!(data::Vector{UInt8}, offset::Int, val::UInt64)
    GC.@preserve data begin
        ptr = pointer(data, offset)
        unsafe_store!(Ptr{UInt64}(ptr), val)
    end
end

# Optimized: Zero-allocation write for 32-bit values
@inline function write_u32_fast(state::PVMState, addr::UInt64, val::UInt32)
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # Single region check for entire word (only writable regions)
        rw = mem.rw_region
        if addr32 >= rw.base && addr32 + 3 < rw.limit
            region_write_u32!(rw.data, Int(addr32 - rw.base + 1), val)
            return
        end

        stack = mem.stack_region
        if addr32 >= stack.base && addr32 + 3 < stack.limit
            region_write_u32!(stack.data, Int(addr32 - stack.base + 1), val)
            return
        end

        # Fallback to byte-by-byte
        write_u8(state, addr, UInt8(val & 0xFF))
        state.status != CONTINUE && return
        write_u8(state, addr + 1, UInt8((val >> 8) & 0xFF))
        state.status != CONTINUE && return
        write_u8(state, addr + 2, UInt8((val >> 16) & 0xFF))
        state.status != CONTINUE && return
        write_u8(state, addr + 3, UInt8((val >> 24) & 0xFF))
    end
end

# Optimized: Zero-allocation read for 16-bit values
@inline function read_u16_fast(state::PVMState, addr::UInt64)::UInt16
    @inbounds begin
        b0 = read_u8(state, addr)
        state.status != CONTINUE && return UInt16(0)
        b1 = read_u8(state, addr + 1)
        return UInt16(b0) | (UInt16(b1) << 8)
    end
end

# Optimized: Zero-allocation write for 16-bit values
@inline function write_u16_fast(state::PVMState, addr::UInt64, val::UInt16)
    @inbounds begin
        write_u8(state, addr, UInt8(val & 0xFF))
        state.status != CONTINUE && return
        write_u8(state, addr + 1, UInt8((val >> 8) & 0xFF))
    end
end

# Optimized: Zero-allocation read for 64-bit values - direct word read
@inline function read_u64_fast(state::PVMState, addr::UInt64)::UInt64
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # Single region check for entire 8-byte word
        ro = mem.ro_region
        if addr32 >= ro.base && addr32 + 7 < ro.limit
            return region_read_u64(ro.data, Int(addr32 - ro.base + 1))
        end

        rw = mem.rw_region
        if addr32 >= rw.base && addr32 + 7 < rw.limit
            return region_read_u64(rw.data, Int(addr32 - rw.base + 1))
        end

        stack = mem.stack_region
        if addr32 >= stack.base && addr32 + 7 < stack.limit
            return region_read_u64(stack.data, Int(addr32 - stack.base + 1))
        end

        # Fallback to two 32-bit reads
        lo = UInt64(read_u32_fast(state, addr))
        state.status != CONTINUE && return UInt64(0)
        hi = UInt64(read_u32_fast(state, addr + 4))
        return lo | (hi << 32)
    end
end

# Optimized: Zero-allocation write for 64-bit values - direct word write
@inline function write_u64_fast(state::PVMState, addr::UInt64, val::UInt64)
    @inbounds begin
        addr32 = UInt32(addr & 0xFFFFFFFF)
        mem = state.memory

        # Single region check for entire 8-byte word (only writable regions)
        rw = mem.rw_region
        if addr32 >= rw.base && addr32 + 7 < rw.limit
            region_write_u64!(rw.data, Int(addr32 - rw.base + 1), val)
            return
        end

        stack = mem.stack_region
        if addr32 >= stack.base && addr32 + 7 < stack.limit
            region_write_u64!(stack.data, Int(addr32 - stack.base + 1), val)
            return
        end

        # Fallback to two 32-bit writes
        write_u32_fast(state, addr, UInt32(val & 0xFFFFFFFF))
        state.status != CONTINUE && return
        write_u32_fast(state, addr + 4, UInt32((val >> 32) & 0xFFFFFFFF))
    end
end

# Optimized: pre-allocate result vector (kept for variable-length reads)
@inline function read_bytes(state::PVMState, addr::UInt64, len::Int)
    result = Vector{UInt8}(undef, len)
    @inbounds for i in 1:len
        result[i] = read_u8(state, addr + UInt64(i - 1))
        if state.status != CONTINUE
            resize!(result, i)  # Trim to actual read length
            return result
        end
    end
    return result
end

# Optimized: inline loop for small writes (kept for variable-length writes)
@inline function write_bytes(state::PVMState, addr::UInt64, data::Vector{UInt8})
    # Disabled stack frame tracing
    @inbounds for i in 1:length(data)
        write_u8(state, addr + UInt64(i - 1), data[i])
        if state.status != CONTINUE
            return
        end
    end
end

# decode helpers - OPTIMIZED with @inline and @inbounds
@inline function decode_immediate(state::PVMState, offset::Int, len::Int)
    @inbounds begin
        val = UInt64(0)
        base = Int(state.pc) + offset
        instrs = state.instructions
        n = length(instrs)
        # Unrolled for common cases
        if len >= 1 && base < n
            val = UInt64(instrs[base + 1])
        end
        if len >= 2 && base + 1 < n
            val |= UInt64(instrs[base + 2]) << 8
        end
        if len >= 3 && base + 2 < n
            val |= UInt64(instrs[base + 3]) << 16
        end
        if len >= 4 && base + 3 < n
            val |= UInt64(instrs[base + 4]) << 24
        end
        if len >= 5 && base + 4 < n
            val |= UInt64(instrs[base + 5]) << 32
        end
        if len >= 6 && base + 5 < n
            val |= UInt64(instrs[base + 6]) << 40
        end
        if len >= 7 && base + 6 < n
            val |= UInt64(instrs[base + 7]) << 48
        end
        if len >= 8 && base + 7 < n
            val |= UInt64(instrs[base + 8]) << 56
        end

        # NOTE: No sign extension here! decode_immediate returns raw unsigned value
        # Use decode_immediate_signed for sign-extended values
        return val
    end
end

function decode_offset(state::PVMState, offset::Int, len::Int)
    val = decode_immediate(state, offset, len)
    # For small lengths, don't extend to 64 bits
    if len <= 4
        # Truncate to actual bit width
        mask = (UInt64(1) << (8*len)) - 1
        val = val & mask
        # Sign extend from actual width
        if len > 0 && (val >> (8*len - 1)) & 1 == 1
            # It's negative, extend the sign
            sign_bits = ~mask
            val = val | sign_bits
        end
    end
    # Convert to Int32 by taking low 32 bits (% gives unchecked truncation) and reinterpreting
    return reinterpret(Int32, val % UInt32)
end

# Decode immediate with sign extension to 64 bits
@inline function decode_immediate_signed(state::PVMState, offset::Int, len::Int)
    val = decode_immediate(state, offset, len)
    # Sign extend from actual width to 64 bits
    if len > 0 && len < 8
        if (val >> (8*len - 1)) & 1 == 1
            # Negative, extend sign
            mask = (UInt64(1) << (8*len)) - 1
            val = val | ~mask
        end
    end
    return val
end

@inline function get_register_index(state::PVMState, byte_offset::Int, nibble::Int)
    @inbounds begin
        pc = state.pc
        if pc + byte_offset >= length(state.instructions)
            return 0
        end
        byte = state.instructions[pc + byte_offset + 1]
        idx = nibble == 0 ? (byte & 0x0F) : (byte >> 4)
        return min(12, idx)
    end
end

# signed/unsigned conversions
@inline function sign_extend_32(val::UInt32)
    (val & 0x80000000 != 0) ? (UInt64(val) | 0xFFFFFFFF00000000) : UInt64(val)
end

@inline function sign_extend_32(val::UInt64)
    low32 = UInt32(val & 0xFFFFFFFF)
    (low32 & 0x80000000 != 0) ? (UInt64(low32) | 0xFFFFFFFF00000000) : UInt64(low32)
end

# sign-extend from immediate byte length to 64 bits
# first sign-extends to 32 bits (like polkavm), then to 64 bits
@inline function sign_extend_imm(val::UInt64, byte_len::Int)
    if byte_len == 0
        return UInt64(0)
    end
    # sign-extend from byte_len bytes to 32 bits
    bit_len = byte_len * 8
    sign_bit = (val >> (bit_len - 1)) & 1
    if sign_bit == 1
        # set all upper bits
        mask = ~((UInt64(1) << bit_len) - 1)
        val32 = UInt32((val | mask) & 0xFFFFFFFF)
    else
        val32 = UInt32(val & 0xFFFFFFFF)
    end
    # then sign-extend from 32 to 64 bits
    return sign_extend_32(val32)
end

@inline to_signed(val::UInt64) = reinterpret(Int64, val)
@inline to_unsigned(val::Int64) = reinterpret(UInt64, val)

function smod(a::T, b::T) where T <: Integer
    if b == 0
        return a
    else
        return sign(a) * (abs(a) % abs(b))
    end
end

# Optimized step with hot-path inlining
# Top 10 opcodes cover 74% of execution - handle them directly
@inline function step!(state::PVMState)
    @inbounds begin
        state.status != CONTINUE && return

        pc_idx = Int(state.pc) + 1
        instrs = state.instructions
        if pc_idx > length(instrs)
            state.gas -= 1
            state.status = PANIC
            return
        end

        opcode = state.opcode_mask[pc_idx] ? instrs[pc_idx] : 0x00
        skip = Int(state.skip_distances[pc_idx])
        state.gas -= 1

        # HOT PATH: top 10 opcodes inline (74% of execution)
        if opcode == 0x95  # 149: add_imm_64 (15.2%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = decode_immediate(state, 2, lx)
            # Sign extend: bytes -> 32-bit -> 64-bit (matching polkavm get64)
            immx = sign_extend_imm(immx, lx)
            state.registers[ra + 1] = state.registers[rb + 1] + immx
            state.pc += 1 + skip

        elseif opcode == 0x7c  # 124: load_ind_u8 (11.2%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            addr = state.registers[rb + 1] + immx
            state.registers[ra + 1] = UInt64(read_u8(state, addr))
            state.pc += 1 + skip

        elseif opcode == 0x82  # 130: load_indirect_u64 (9.7%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            addr = state.registers[rb + 1] + immx
            state.registers[ra + 1] = read_u64_fast(state, addr)
            state.pc += 1 + skip

        # NOTE: 0x51 (81) removed from hot path - it's branch_eq_imm not branch_ne
        # The cold path handles it correctly

        elseif opcode == 0x7b  # 123: store_ind_u64 (7.3%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            write_u64_fast(state, state.registers[rb + 1] + immx, state.registers[ra + 1])
            state.pc += 1 + skip

        elseif opcode == 0x64  # 100: move_reg (4.9%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            state.registers[ra + 1] = state.registers[rb + 1]
            state.pc += 1 + skip

        # NOTE: 0x50 (80) removed from hot path - it's load_imm_jump not branch_eq
        # The cold path handles it correctly

        elseif opcode == 0x80  # 128: load_ind_u32 (4.6%) - load from register + immediate
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            addr = state.registers[rb + 1] + immx
            val = read_u32_fast(state, addr)
            state.registers[ra + 1] = sign_extend_32(val)
            state.pc += 1 + skip

        elseif opcode == 0xaa  # 170: branch_eq (3.6%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            offset = decode_offset(state, 2, min(4, max(0, skip - 1)))
            if state.registers[ra + 1] == state.registers[rb + 1]
                state.pc = UInt32((Int64(state.pc) + offset) & 0xFFFFFFFF)
            else
                state.pc += 1 + skip
            end

        elseif opcode == 0x97  # 151: shlo_l_imm_64 (shift_logical_left_imm_64) (3.3%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = decode_immediate(state, 2, lx)
            shift = immx % 64
            state.registers[ra + 1] = UInt64(state.registers[rb + 1] << shift)
            state.pc += 1 + skip

        elseif opcode == 0xab  # 171: branch_ne (12.9%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            offset = decode_offset(state, 2, lx)
            if state.registers[ra + 1] != state.registers[rb + 1]
                state.pc = UInt32((Int64(state.pc) + offset) & 0xFFFFFFFF)
            else
                state.pc += 1 + skip
            end

        elseif opcode == 0x78  # 120: store_ind_u8 (12.8%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            write_u8(state, state.registers[rb + 1] + immx, UInt8(state.registers[ra + 1] & 0xFF))
            state.pc += 1 + skip

        elseif opcode == 0xd4  # 212: or (3.4%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            rd = get_register_index(state, 2, 0)
            state.registers[rd + 1] = state.registers[ra + 1] | state.registers[rb + 1]
            state.pc += 1 + skip

        elseif opcode == 0x81  # 129: load_ind_i32 (3.3%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            addr = state.registers[rb + 1] + immx
            val = read_u32_fast(state, addr)
            state.registers[ra + 1] = sign_extend_32(val)
            state.pc += 1 + skip

        elseif opcode == 0x7a  # 122: store_ind_u32 (3.2%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
            write_u32_fast(state, state.registers[rb + 1] + immx, UInt32(state.registers[ra + 1] % 2^32))
            state.pc += 1 + skip

        elseif opcode == 0x8b  # 139: shlo_r_imm_32 (3.2%)
            ra = get_register_index(state, 1, 0)
            rb = get_register_index(state, 1, 1)
            lx = min(4, max(0, skip - 1))
            immx = decode_immediate(state, 2, lx)
            shift = immx % 32
            result = UInt32((state.registers[rb + 1] % 2^32) >> shift)
            state.registers[ra + 1] = sign_extend_32(result)
            state.pc += 1 + skip

        else
            # COLD PATH: all other opcodes via execute_instruction!
            execute_instruction_cold!(state, opcode, skip)
        end
    end
end

# Bulk step function - runs many steps before returning, reduces call overhead
function step_n!(state::PVMState, n::Int)
    @inbounds for _ in 1:n
        state.status != CONTINUE && return
        step!(state)
    end
end

# Cold path for less common instructions (gas already charged in step!)
@noinline function execute_instruction_cold!(state::PVMState, opcode::UInt8, skip::Int)
    # Delegate to original handler but don't charge gas again
    execute_instruction_impl!(state, opcode, skip)
    # Advance PC for non-branch instructions
    if state.status == CONTINUE && !is_branch_instruction(opcode)
        state.pc += 1 + skip
    end
end

@inline function is_branch_instruction(opcode::UInt8)
    return opcode == 40 || opcode == 50 || opcode == 180 ||
           (170 <= opcode <= 175) || (80 <= opcode <= 90)
end

# Implementation for cold-path opcodes (gas already charged by step!)
function execute_instruction_impl!(state::PVMState, opcode::UInt8, skip::Int)
    if opcode == 0  # trap
        state.status = PANIC
        
    elseif opcode == 1  # fallthrough
        # nop

    elseif opcode == 2  # memset (PolkaVM extension)
        # memset rd, rs, value - fills memory; for interpreter, just advance PC
        # TODO: implement properly if needed

    elseif opcode == 3  # unlikely (PolkaVM branch hint)
        # Tells JIT that branch is unlikely; interpreter treats as nop

    elseif opcode == 0x0A  # ecalli
        imm = decode_immediate(state, 1, min(4, skip))
        state.status = HOST
        state.host_call_id = UInt32(imm)

    elseif opcode == 16  # store_u32 sp-relative (0x10)
        # Store 32-bit value to [sp + offset]
        # Format: 0x10 <offset_byte>
        # The register is RA (register 1) implicitly
        offset = decode_immediate(state, 1, 1)  # Only 1 byte for offset
        addr = state.registers[2 + 1] + offset  # SP is register 2
        val = UInt32(state.registers[1 + 1] & 0xFFFFFFFF)  # RA is register 1
        write_u32_fast(state, addr, val)  # Zero-allocation write

    elseif opcode == 0x11  # add_imm sp (register + immediate)
        # For 0x11, it's always SP (register 2)
        rd = 2  # SP is register 2
        imm_bytes = 1  # Only 1 byte immediate for 0x11
        imm = decode_immediate(state, 1, imm_bytes)
        # Sign extend for negative values
        if imm_bytes > 0 && (imm >> (8*imm_bytes - 1)) & 1 == 1
            imm |= ~((UInt64(1) << (8*imm_bytes)) - 1)
        end
        # DEBUG add_imm
        # Perform addition with wrapping
        state.registers[rd + 1] = (state.registers[rd + 1] + imm) & 0xFFFFFFFFFFFFFFFF
        # After add_imm

    elseif opcode == 21  # store_u32 sp-relative (0x15)
        # Store S0 (register 5) to [sp + 0]
        # Format: 0x15
        addr = state.registers[2 + 1]  # SP is register 2
        val = UInt32(state.registers[5 + 1] & 0xFFFFFFFF)  # S0 is register 5
        write_u32_fast(state, addr, val)  # Zero-allocation write

    elseif opcode == 20  # load_imm_64
        ra = get_register_index(state, 1, 0)
        imm = decode_immediate(state, 2, 8)
        state.registers[ra + 1] = imm
        
    # store immediate instructions (30-33)
    elseif opcode == 30  # store_imm_u8
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        write_u8(state, immx, UInt8(immy % 256))
        
    elseif opcode == 31  # store_imm_u16
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        write_u16_fast(state, immx, UInt16(immy % 2^16))
        
    elseif opcode == 32  # store_imm_u32
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        write_u32_fast(state, immx, UInt32(immy % 2^32))

    elseif opcode == 33  # store_imm_u64
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        write_u64_fast(state, immx, immy)
        
    elseif opcode == 40  # jump
        offset = decode_offset(state, 1, min(4, skip))
        target = UInt32((Int32(state.pc) + offset) % 2^32)
        state.pc = target
        
    elseif opcode == 50  # jump_ind
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        addr = (state.registers[ra + 1] + immx) % 2^32

        # dynamic jump through table
        # Halt address: 2^32 - 2^16 = 0xFFFF0000 = 4294901760
        if addr == UInt64(0xFFFF0000)
            state.status = HALT
        elseif addr == 0 || addr % DYNAM_ALIGN != 0
            state.status = PANIC
        else
            idx = div(addr, DYNAM_ALIGN) - 1
            if idx >= length(state.jump_table)
                state.status = PANIC
            else
                state.pc = state.jump_table[idx + 1]
            end
        end
        
    # load/store with register + immediate (51-62)
    elseif opcode == 51  # load_imm
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        # sign-extend from immediate byte length to 64 bits (matching polkavm behavior)
        state.registers[ra + 1] = sign_extend_imm(immx, lx)
        
    elseif opcode == 52  # load_u8
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = UInt64(read_u8(state, immx))
        # Log input buffer reads
        step = get(task_local_storage(), :pvm_step_count, 0)
        if step >= 1 && step < 30
            if immx >= 0xfef00000  # Input buffer region
                println("    [LOAD_U8] step=$step addr=0x$(string(immx, base=16, pad=8)) value=$val")
            end
        end
        state.registers[ra + 1] = val
        
    elseif opcode == 53  # load_i8
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = read_u8(state, immx)
        state.registers[ra + 1] = val >= 128 ? UInt64(val) | 0xFFFFFFFFFFFFFF00 : UInt64(val)
        
    elseif opcode == 54  # load_u16
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, immx, 2)
        state.registers[ra + 1] = UInt64(bytes[1]) | (UInt64(bytes[2]) << 8)
        
    elseif opcode == 55  # load_i16
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, immx, 2)
        val = UInt16(bytes[1]) | (UInt16(bytes[2]) << 8)
        state.registers[ra + 1] = val >= 32768 ? UInt64(val) | 0xFFFFFFFFFFFF0000 : UInt64(val)
        
    elseif opcode == 56  # load_u32
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, immx, 4)
        val = UInt64(bytes[1]) | (UInt64(bytes[2]) << 8) | (UInt64(bytes[3]) << 16) | (UInt64(bytes[4]) << 24)
        # Log input buffer reads
        step = get(task_local_storage(), :pvm_step_count, 0)
        if step >= 1 && step < 30
            if immx >= 0xfef00000  # Input buffer region
                println("    [LOAD_U32] step=$step addr=0x$(string(immx, base=16, pad=8)) value=$val")
            end
        end
        state.registers[ra + 1] = val
        
    elseif opcode == 57  # load_i32
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, immx, 4)
        val = UInt32(bytes[1]) | (UInt32(bytes[2]) << 8) | (UInt32(bytes[3]) << 16) | (UInt32(bytes[4]) << 24)
        state.registers[ra + 1] = sign_extend_32(val)
        
    elseif opcode == 58  # load_u64
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, immx, 8)
        state.registers[ra + 1] = sum(UInt64(bytes[i+1]) << (8*i) for i in 0:7)
        
    elseif opcode == 59  # store_u8
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        write_u8(state, immx, UInt8(state.registers[ra + 1] & 0xFF))
        
    elseif opcode == 60  # store_u16
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        write_u16_fast(state, immx, UInt16(state.registers[ra + 1] % 2^16))
        
    elseif opcode == 61  # store_u32
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        write_u32_fast(state, immx, UInt32(state.registers[ra + 1] % 2^32))

    elseif opcode == 62  # store_u64
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        write_u64_fast(state, immx, state.registers[ra + 1])
        
    # instructions with one register & two immediates (70-73)
    elseif opcode == 70  # store_imm_ind_u8
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        write_u8(state, addr, UInt8(immy & 0xFF))
        
    elseif opcode == 71  # store_imm_ind_u16
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        val = immy % 2^16
        write_bytes(state, addr, [UInt8(val & 0xFF), UInt8((val >> 8) & 0xFF)])
        
    elseif opcode == 72  # store_imm_ind_u32
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        immy = sign_extend_imm(decode_immediate(state, 2 + lx, ly), ly)
        addr = state.registers[ra + 1] + immx
        val = UInt32(immy % UInt64(2^32))
        write_u32_fast(state, addr, val)  # Zero-allocation write
        
    elseif opcode == 73  # store_imm_ind_u64
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        immy = sign_extend_imm(decode_immediate(state, 2 + lx, ly), ly)
        addr = state.registers[ra + 1] + immx
        write_u64_fast(state, addr, immy)  # Zero-allocation write
        
    # instructions with one register, one immediate and one offset (80-90)
    elseif opcode == 80  # load_imm_jump
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        # sign-extend the immediate value (like polkavm does)
        state.registers[ra + 1] = sign_extend_imm(immx, lx)
        state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        
    elseif opcode == 81  # branch_eq_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] == immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 82  # branch_ne_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] != immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 83  # branch_lt_u_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] < immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 84  # branch_le_u_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] <= immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 85  # branch_ge_u_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] >= immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 86  # branch_gt_u_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] > immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 87  # branch_lt_s_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, Int(lx))
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + Int(lx), Int(ly))
        if to_signed(state.registers[ra + 1]) < to_signed(immx)
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 88  # branch_le_s_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if to_signed(state.registers[ra + 1]) <= to_signed(immx)
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 89  # branch_ge_s_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if to_signed(state.registers[ra + 1]) >= to_signed(immx)
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    elseif opcode == 90  # branch_gt_s_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        if to_signed(state.registers[ra + 1]) > to_signed(immx)
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    # register-register operations (100-111)
    elseif opcode == 100  # move_reg
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = state.registers[ra + 1]
        
    elseif opcode == 101  # sbrk
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)

        # Get increment value from register ra
        increment = Int64(state.registers[ra + 1])

        # If increment == 0, query current heap pointer
        if increment == 0
            state.registers[rd + 1] = UInt64(state.memory.current_heap_pointer)
        else
            # Record current heap pointer to return
            old_heap_pointer = state.memory.current_heap_pointer
            state.registers[rd + 1] = UInt64(old_heap_pointer)

            # Calculate new heap pointer
            new_heap_pointer_64 = UInt64(state.memory.current_heap_pointer) + UInt64(increment)

            # Bounds check - don't allow heap to grow beyond reasonable limits
            if new_heap_pointer_64 > UInt64(0x80000000)  # Max 2GB heap
                state.status = PANIC
            else
                next_page_boundary = P_func(state.memory.current_heap_pointer)

                # If crossing page boundary, allocate new pages
                if new_heap_pointer_64 > UInt64(next_page_boundary)
                    final_boundary = P_func(UInt32(new_heap_pointer_64))
                    idx_start = div(next_page_boundary, UInt32(PAGE_SIZE))
                    idx_end = div(final_boundary, UInt32(PAGE_SIZE))

                    # Pre-allocate sparse pages for heap in the new range
                    for page_idx in idx_start:(idx_end-1)
                        state.memory.sparse.page_perms[page_idx] = true  # writable
                    end
                end

                # Advance the heap pointer
                state.memory.current_heap_pointer = UInt32(new_heap_pointer_64)
            end
        end

    elseif opcode == 102  # count_set_bits_64
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = count_ones(state.registers[ra + 1])
        
    elseif opcode == 103  # count_set_bits_32
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = count_ones(UInt32(state.registers[ra + 1] % 2^32))
        
    elseif opcode == 104  # leading_zero_bits_64
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = leading_zeros(state.registers[ra + 1])
        
    elseif opcode == 105  # leading_zero_bits_32
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = leading_zeros(UInt32(state.registers[ra + 1] % 2^32))
        
    elseif opcode == 106  # trailing_zero_bits_64
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = trailing_zeros(state.registers[ra + 1])
        
    elseif opcode == 107  # trailing_zero_bits_32
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = trailing_zeros(UInt32(state.registers[ra + 1] % 2^32))
        
    elseif opcode == 108  # sign_extend_8
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        val = UInt8(state.registers[ra + 1] % 256)
        state.registers[rd + 1] = val >= 128 ? UInt64(val) | 0xFFFFFFFFFFFFFF00 : UInt64(val)
        
    elseif opcode == 109  # sign_extend_16
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        val = UInt16(state.registers[ra + 1] % 2^16)
        state.registers[rd + 1] = val >= 32768 ? UInt64(val) | 0xFFFFFFFFFFFF0000 : UInt64(val)
        
    elseif opcode == 110  # zero_extend_16
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        state.registers[rd + 1] = state.registers[ra + 1] % 2^16
        
    elseif opcode == 111  # reverse_bytes
        rd = get_register_index(state, 1, 0)
        ra = get_register_index(state, 1, 1)
        val = state.registers[ra + 1]
        reversed = UInt64(0)
        for i in 0:7
            reversed |= ((val >> (8*i)) & 0xFF) << (8*(7-i))
        end
        state.registers[rd + 1] = reversed

    elseif opcode == 0x7A  # store_u32_ind (store register to [base + offset])
        rs = get_register_index(state, 1, 0)  # Source register
        rb = get_register_index(state, 1, 1)  # Base register
        lx = min(skip - 1, 4)
        offset = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        addr = state.registers[rb + 1] + offset
        val = UInt32(state.registers[rs + 1] & 0xFFFFFFFF)
        write_u32_fast(state, addr, val)  # Zero-allocation write

    # Note: opcode 0x78 (120) is store_ind_u8, handled below in the 120-161 range

    elseif opcode == 120 && false  # DISABLED: load_i32_ind (load signed 32-bit from [base + offset])
        rd = get_register_index(state, 1, 0)  # Dest register
        rb = get_register_index(state, 1, 1)  # Base register
        offset = decode_immediate(state, 2, min(skip - 1, 4))
        addr = state.registers[rb + 1] + offset
        bytes = read_bytes(state, addr, 4)
        if state.status == CONTINUE && length(bytes) == 4
            val = UInt32(bytes[1]) | (UInt32(bytes[2]) << 8) | (UInt32(bytes[3]) << 16) | (UInt32(bytes[4]) << 24)
            # Sign extend
            if val & 0x80000000 != 0
                state.registers[rd + 1] = UInt64(val) | 0xFFFFFFFF00000000
            else
                state.registers[rd + 1] = UInt64(val)
            end
        end

    elseif opcode == 0x81  # load_i32 immediate address
        rd = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(skip - 1, 4)
        offset = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        addr = state.registers[rb + 1] + offset
        val = read_u32_fast(state, addr)  # Zero-allocation read
        if state.status == CONTINUE
            # Sign extend
            if val & 0x80000000 != 0
                state.registers[rd + 1] = UInt64(val) | 0xFFFFFFFF00000000
            else
                state.registers[rd + 1] = UInt64(val)
            end
        end

    elseif opcode == 0x83  # add_imm_32
        rd = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        imm = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        # 32-bit add with sign extension (i32 result)
        result = UInt32((state.registers[rb + 1] + imm) % UInt64(2^32))
        state.registers[rd + 1] = sign_extend_32(result)

    # Note: opcode 0x32 (50) is jump_ind, already handled above at line 379
    # The "ret" instruction does not exist in the PVM spec

    # Add these instructions after opcode 111 and before 190:

    # Two registers & one immediate (120-161)
    elseif opcode == 120  # store_ind_u8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        write_u8(state, state.registers[rb + 1] + immx, UInt8(state.registers[ra + 1] & 0xFF))

    elseif opcode == 121  # store_ind_u16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        write_u16_fast(state, state.registers[rb + 1] + immx, UInt16(state.registers[ra + 1] % 2^16))

    elseif opcode == 122  # store_ind_u32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        write_u32_fast(state, state.registers[rb + 1] + immx, UInt32(state.registers[ra + 1] % 2^32))

    elseif opcode == 123  # store_ind_u64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        val = state.registers[ra + 1]
        addr = state.registers[rb + 1] + immx
        if TRACE_EXECUTION
            println("    [STORE_IND_U64] val=0x$(string(val, base=16)) to addr=0x$(string(addr, base=16)) (r$(rb)+$(immx))")
        end
        write_u64_fast(state, addr, val)  # Zero-allocation write

    elseif opcode == 124  # load_ind_u8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        addr = state.registers[rb + 1] + immx
        state.registers[ra + 1] = UInt64(read_u8(state, addr))

    elseif opcode == 125  # load_ind_i8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        val = read_u8(state, state.registers[rb + 1] + immx)
        state.registers[ra + 1] = val >= 128 ? UInt64(val) | 0xFFFFFFFFFFFFFF00 : UInt64(val)

    elseif opcode == 126  # load_ind_u16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        val = read_u16_fast(state, state.registers[rb + 1] + immx)
        state.registers[ra + 1] = UInt64(val)

    elseif opcode == 127  # load_ind_i16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        val = read_u16_fast(state, state.registers[rb + 1] + immx)
        state.registers[ra + 1] = val >= 32768 ? UInt64(val) | 0xFFFFFFFFFFFF0000 : UInt64(val)

    elseif opcode == 128  # load_ind_u32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        addr = state.registers[rb + 1] + immx
        val = read_u32_fast(state, addr)  # Zero-allocation read
        state.status != CONTINUE && return
        state.registers[ra + 1] = UInt64(val)

    elseif opcode == 130  # load_ind_u64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        addr = state.registers[rb + 1] + immx
        val = read_u64_fast(state, addr)  # Zero-allocation read
        state.status != CONTINUE && return
        state.registers[ra + 1] = val

    elseif opcode == 132  # and_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] & immx
        
    elseif opcode == 133  # xor_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] ⊻ immx
        
    elseif opcode == 134  # or_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] | immx
        
    elseif opcode == 135  # mul_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        result = UInt32((state.registers[rb + 1] * immx) % 2^32)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 136  # set_lt_u_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] < immx ? 1 : 0

    elseif opcode == 137  # set_lt_s_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = to_signed(state.registers[rb + 1]) < to_signed(immx) ? 1 : 0
        
    elseif opcode == 138  # shlo_l_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 32
        result = UInt32((state.registers[rb + 1] << shift) % 2^32)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 139  # shlo_r_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 32
        result = UInt32((state.registers[rb + 1] % 2^32) >> shift)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 140  # shar_r_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 32
        val = reinterpret(Int32, UInt32(state.registers[rb + 1] % 2^32))
        result = val >> shift
        state.registers[ra + 1] = sign_extend_32(reinterpret(UInt32, result))
        
    elseif opcode == 141  # neg_add_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = sign_extend_imm(decode_immediate(state, 2, lx), lx)
        result = UInt32((immx + UInt64(2^32) - state.registers[rb + 1]) % UInt64(2^32))
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 142  # set_gt_u_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] > immx ? 1 : 0

    elseif opcode == 143  # set_gt_s_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = to_signed(state.registers[rb + 1]) > to_signed(immx) ? 1 : 0
        
    elseif opcode == 144  # shlo_l_imm_alt_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = state.registers[rb + 1] % 32
        result = UInt32((immx << shift) % 2^32)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 145  # shlo_r_imm_alt_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = state.registers[rb + 1] % 32
        result = UInt32((immx % 2^32) >> shift)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 146  # shar_r_imm_alt_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = state.registers[rb + 1] % 32
        val = reinterpret(Int32, UInt32(immx % 2^32))
        result = val >> shift
        state.registers[ra + 1] = sign_extend_32(reinterpret(UInt32, result))
        
    elseif opcode == 147  # cmov_iz_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] == 0 ? immx : state.registers[ra + 1]

    elseif opcode == 148  # cmov_nz_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = state.registers[rb + 1] != 0 ? immx : state.registers[ra + 1]

    elseif opcode == 149  # add_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = UInt64(state.registers[rb + 1] + immx)

    elseif opcode == 150  # mul_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = UInt64(state.registers[rb + 1] * immx)
        
    elseif opcode == 151  # shlo_l_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 64
        state.registers[ra + 1] = UInt64(state.registers[rb + 1] << shift)
        
    elseif opcode == 152  # shlo_r_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 64
        state.registers[ra + 1] = state.registers[rb + 1] >> shift
        
    elseif opcode == 153  # shar_r_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = immx % 64
        val = to_signed(state.registers[rb + 1])
        state.registers[ra + 1] = to_unsigned(val >> shift)
        
    elseif opcode == 154  # neg_add_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        state.registers[ra + 1] = UInt64(immx - state.registers[rb + 1])

    elseif opcode == 155  # shlo_l_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        shift = state.registers[rb + 1] % 64
        state.registers[ra + 1] = UInt64(immx << shift)

    elseif opcode == 156  # shlo_r_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        shift = state.registers[rb + 1] % 64
        state.registers[ra + 1] = immx >> shift
        
    elseif opcode == 157  # shar_r_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        shift = state.registers[rb + 1] % 64
        val = to_signed(immx)
        state.registers[ra + 1] = to_unsigned(val >> shift)

    elseif opcode == 158  # rot_r_64_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        rot = immx % 64
        val = state.registers[rb + 1]
        state.registers[ra + 1] = UInt64((val >> rot) | (val << (64 - rot)))

    elseif opcode == 159  # rot_r_64_imm_alt
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        immx = sign_extend_imm(immx, lx)
        rot = state.registers[rb + 1] % 64
        state.registers[ra + 1] = UInt64((immx >> rot) | (immx << (64 - rot)))
        
    elseif opcode == 160  # rot_r_32_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        rot = immx % 32
        val = UInt32(state.registers[rb + 1] % 2^32)
        result = ((val >> rot) | (val << (32 - rot))) % 2^32
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 161  # rot_r_32_imm_alt
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        rot = state.registers[rb + 1] % 32
        val = UInt32(immx % 2^32)
        result = ((val >> rot) | (val << (32 - rot))) % 2^32
        state.registers[ra + 1] = sign_extend_32(result)

    # Add branch instructions 172-175 after 171:
    elseif opcode == 172  # branch_lt_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        if state.registers[ra + 1] < state.registers[rb + 1]
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    elseif opcode == 173  # branch_lt_s
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        if to_signed(state.registers[ra + 1]) < to_signed(state.registers[rb + 1])
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    elseif opcode == 174  # branch_ge_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        va = state.registers[ra + 1]
        vb = state.registers[rb + 1]
        taken = va >= vb
        if TRACE_EXECUTION
            println("    [BRANCH_GE_U] r$(ra)($(va)) >= r$(rb)($(vb)) = $(taken), offset=$(offset)")
        end
        if taken
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    elseif opcode == 175  # branch_ge_s
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        if to_signed(state.registers[ra + 1]) >= to_signed(state.registers[rb + 1])
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end

    # Add opcode 180:
    elseif opcode == 180  # load_imm_jump_ind
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = Int(min(4, state.instructions[state.pc + 3] % 8))
        ly = min(4, max(0, skip - lx - 2))
        immx = decode_immediate(state, 3, lx)
        immy = decode_immediate(state, 3 + lx, ly)
        # Read rb BEFORE writing to ra (in case ra == rb)
        rb_val = state.registers[rb + 1]
        # sign-extend the immediate value (like polkavm does)
        state.registers[ra + 1] = sign_extend_imm(immx, lx)
        addr = (rb_val + immy) % 2^32
        if addr == 2^32 - 2^16
            state.status = HALT
        elseif addr == 0 || addr % DYNAM_ALIGN != 0
            state.status = PANIC
        else
            idx = div(addr, DYNAM_ALIGN) - 1
            if idx >= length(state.jump_table)
                state.status = PANIC
            else
                state.pc = state.jump_table[idx + 1]
            end
        end

    # Add division and remainder operations 194-209 after 193:
    elseif opcode == 194  # div_s_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = reinterpret(Int32, UInt32(state.registers[ra + 1] % 2^32))
        b = reinterpret(Int32, UInt32(state.registers[rb + 1] % 2^32))
        if b == 0
            state.registers[rd + 1] = typemax(UInt64)
        elseif a == typemin(Int32) && b == -1
            state.registers[rd + 1] = sign_extend_32(reinterpret(UInt32, a))
        else
            state.registers[rd + 1] = sign_extend_32(reinterpret(UInt32, Int32(div(a, b))))
        end
        
    elseif opcode == 195  # rem_u_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        divisor = UInt32(state.registers[rb + 1] % 2^32)
        if divisor == 0
            state.registers[rd + 1] = sign_extend_32(UInt32(state.registers[ra + 1] % 2^32))
        else
            result = UInt32(state.registers[ra + 1] % 2^32) % divisor
            state.registers[rd + 1] = sign_extend_32(result)
        end
        
    elseif opcode == 196  # rem_s_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = reinterpret(Int32, UInt32(state.registers[ra + 1] % 2^32))
        b = reinterpret(Int32, UInt32(state.registers[rb + 1] % 2^32))
        if b == 0
            # Division by zero returns the dividend
            state.registers[rd + 1] = sign_extend_32(reinterpret(UInt32, a))
        elseif a == typemin(Int32) && b == -1
            state.registers[rd + 1] = 0
        else
            result = smod(a, b)
            state.registers[rd + 1] = sign_extend_32(reinterpret(UInt32, result))
        end
        
    elseif opcode == 197  # shlo_l_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 32
        result = UInt32((state.registers[ra + 1] << shift) % 2^32)
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 198  # shlo_r_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 32
        result = UInt32((state.registers[ra + 1] % 2^32) >> shift)
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 199  # shar_r_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 32
        val = reinterpret(Int32, UInt32(state.registers[ra + 1] % 2^32))
        result = val >> shift
        state.registers[rd + 1] = sign_extend_32(reinterpret(UInt32, result))

    # 200-202 already implemented, continuing from 203:
    elseif opcode == 203  # div_u_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        if state.registers[rb + 1] == 0
            state.registers[rd + 1] = typemax(UInt64)
        else
            state.registers[rd + 1] = div(state.registers[ra + 1], state.registers[rb + 1])
        end
        
    elseif opcode == 204  # div_s_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = to_signed(state.registers[ra + 1])
        b = to_signed(state.registers[rb + 1])
        if b == 0
            state.registers[rd + 1] = typemax(UInt64)
        elseif a == typemin(Int64) && b == -1
            state.registers[rd + 1] = state.registers[ra + 1]
        else
            state.registers[rd + 1] = to_unsigned(div(a, b))
        end
        
    elseif opcode == 205  # rem_u_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        if state.registers[rb + 1] == 0
            state.registers[rd + 1] = state.registers[ra + 1]
        else
            state.registers[rd + 1] = state.registers[ra + 1] % state.registers[rb + 1]
        end
        
    elseif opcode == 206  # rem_s_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = to_signed(state.registers[ra + 1])
        b = to_signed(state.registers[rb + 1])
        if a == typemin(Int64) && b == -1
            state.registers[rd + 1] = 0
        else
            result = smod(a, b)
            state.registers[rd + 1] = to_unsigned(result)
        end
        
    elseif opcode == 207  # shlo_l_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 64
        state.registers[rd + 1] = UInt64(state.registers[ra + 1] << shift)
        
    elseif opcode == 208  # shlo_r_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 64
        state.registers[rd + 1] = state.registers[ra + 1] >> shift
        
    elseif opcode == 209  # shar_r_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        shift = state.registers[rb + 1] % 64
        val = to_signed(state.registers[ra + 1])
        state.registers[rd + 1] = to_unsigned(val >> shift)

    # 210-212 already implemented, continuing from 213:
    elseif opcode == 213  # mul_upper_s_s
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = Int128(to_signed(state.registers[ra + 1]))
        b = Int128(to_signed(state.registers[rb + 1]))
        prod = a * b
        state.registers[rd + 1] = to_unsigned(Int64(prod >> 64))
        
    elseif opcode == 214  # mul_upper_u_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = UInt128(state.registers[ra + 1])
        b = UInt128(state.registers[rb + 1])
        prod = a * b
        state.registers[rd + 1] = UInt64(prod >> 64)
        
    elseif opcode == 215  # mul_upper_s_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = Int128(to_signed(state.registers[ra + 1]))
        b = Int128(state.registers[rb + 1])
        prod = a * b
        state.registers[rd + 1] = to_unsigned(Int64(prod >> 64))
        
    elseif opcode == 216  # set_lt_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[ra + 1] < state.registers[rb + 1] ? 1 : 0
        
    elseif opcode == 217  # set_lt_s
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = to_signed(state.registers[ra + 1]) < to_signed(state.registers[rb + 1]) ? 1 : 0
        
    elseif opcode == 218  # cmov_iz
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[rb + 1] == 0 ? state.registers[ra + 1] : state.registers[rd + 1]
        
    elseif opcode == 219  # cmov_nz
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[rb + 1] != 0 ? state.registers[ra + 1] : state.registers[rd + 1]
        
    elseif opcode == 220  # rot_l_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        rot = state.registers[rb + 1] % 64
        val = state.registers[ra + 1]
        state.registers[rd + 1] = UInt64((val << rot) | (val >> (64 - rot)))
        
    elseif opcode == 221  # rot_l_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        rot = state.registers[rb + 1] % 32
        val = UInt32(state.registers[ra + 1] % 2^32)
        result = ((val << rot) | (val >> (32 - rot))) % 2^32
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 222  # rot_r_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        rot = state.registers[rb + 1] % 64
        val = state.registers[ra + 1]
        state.registers[rd + 1] = UInt64((val >> rot) | (val << (64 - rot)))
        
    elseif opcode == 223  # rot_r_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        rot = state.registers[rb + 1] % 32
        val = UInt32(state.registers[ra + 1] % 2^32)
        result = ((val >> rot) | (val << (32 - rot))) % 2^32
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 224  # and_inv
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        result = state.registers[ra + 1] & ~state.registers[rb + 1]
        step = get(task_local_storage(), :pvm_step_count, 0)
        if TRACE_EXECUTION && step < 30
            println("    [AND_INV] r$rd = r$ra(0x$(string(state.registers[ra + 1], base=16))) & ~r$rb(0x$(string(state.registers[rb + 1], base=16))) = 0x$(string(result, base=16))")
        end
        state.registers[rd + 1] = result
        
    elseif opcode == 225  # or_inv
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[ra + 1] | ~state.registers[rb + 1]
        
    elseif opcode == 226  # xnor
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = ~(state.registers[ra + 1] ⊻ state.registers[rb + 1])
        
    elseif opcode == 227  # max
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = to_signed(state.registers[ra + 1])
        b = to_signed(state.registers[rb + 1])
        state.registers[rd + 1] = to_unsigned(max(a, b))
        
    elseif opcode == 228  # max_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = max(state.registers[ra + 1], state.registers[rb + 1])
        
    elseif opcode == 229  # min
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        a = to_signed(state.registers[ra + 1])
        b = to_signed(state.registers[rb + 1])
        state.registers[rd + 1] = to_unsigned(min(a, b))
        
    elseif opcode == 230  # min_u
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = min(state.registers[ra + 1], state.registers[rb + 1])
        
    # three register operations (190-230)
    elseif opcode == 0xBE && state.pc == 11  # Special case: ecalli at PC=11
        # At PC=11 we should have ecalli 0
        state.status = HOST
        state.registers[1] = 0  # host call id 0
        state.pc += 1  # Move past the ecalli

    elseif opcode == 190  # add_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        result = UInt32((state.registers[ra + 1] + state.registers[rb + 1]) % 2^32)
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 191  # sub_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        result = UInt32((state.registers[ra + 1] + 2^32 - (state.registers[rb + 1] % 2^32)) % 2^32)
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 192  # mul_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        result = UInt32((state.registers[ra + 1] * state.registers[rb + 1]) % 2^32)
        state.registers[rd + 1] = sign_extend_32(result)
        
    elseif opcode == 193  # div_u_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        divisor = UInt32(state.registers[rb + 1] % 2^32)
        if divisor == 0
            state.registers[rd + 1] = typemax(UInt64)
        else
            result = div(UInt32(state.registers[ra + 1] % 2^32), divisor)
            state.registers[rd + 1] = sign_extend_32(result)
        end
        
    elseif opcode == 200  # add_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = UInt64(state.registers[ra + 1] + state.registers[rb + 1])
        
    elseif opcode == 201  # sub_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = UInt64(state.registers[ra + 1] - state.registers[rb + 1])
        
    elseif opcode == 202  # mul_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = UInt64(state.registers[ra + 1] * state.registers[rb + 1])
        
    elseif opcode == 210  # and
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[ra + 1] & state.registers[rb + 1]
        
    elseif opcode == 211  # xor
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[ra + 1] ⊻ state.registers[rb + 1]
        
    elseif opcode == 212  # or
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        state.registers[rd + 1] = state.registers[ra + 1] | state.registers[rb + 1]
        
    # branch instructions (170-175)
    elseif opcode == 170  # branch_eq
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        if state.registers[ra + 1] == state.registers[rb + 1]
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    elseif opcode == 171  # branch_ne
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        offset = decode_offset(state, 2, lx)
        if state.registers[ra + 1] != state.registers[rb + 1]
            state.pc = UInt32((Int32(state.pc) + offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    else
        # undefined opcode -> trap
        println("PANIC: Unhandled opcode $(opcode) (0x$(string(opcode, base=16))) at PC=$(state.pc)")
        state.status = PANIC
    end
end


# main execution entry
function execute(program::Vector{UInt8}, input::Vector{UInt8}, gas::UInt64)
    result = deblob(program)
    if result === nothing
        return (PANIC, UInt8[], 0, Vector{UInt8}[])
    end
    
    instructions, opcode_mask, jump_table = result
    
    # initialize state
    state = PVMState(
        UInt32(0),  # pc starts at 0
        CONTINUE,  # status
        Int64(gas),  # gas
        instructions,  # instructions
        opcode_mask,  # opcode_mask
        precompute_skip_distances(opcode_mask),  # skip_distances
        zeros(UInt64, 13),  # registers
        Memory(),  # memory
        jump_table,  # jump_table
        UInt32(0),  # host_call_id
        Vector{UInt8}[],  # exports
        Dict{UInt32, GuestPVM}()  # machines
    )
    
    # setup memory layout with program segments
    setup_memory!(state, input, ro_data, rw_data, stack_pages, stack_bytes)
    
    # run until halt
    initial_gas = state.gas
    # Empty context for now - will be populated when integrating with work packages
    context = nothing
    invocation_type = :refine  # Default to refine for testing

    while state.gas > 0
        if state.status == CONTINUE
            step!(state)
        elseif state.status == HOST
            # Save PC before host call
            pc_before = state.pc

            # Handle host call
            host_call_id = Int(state.host_call_id)
            state = HostCalls.dispatch_host_call(host_call_id, state, context, invocation_type)

            # Resume execution if no error
            if state.status == HOST
                state.status = CONTINUE
                # Advance PC past ecalli instruction
                # ecalli format: opcode (1 byte) + immediate (skip bytes)
                skip = skip_distance(state.opcode_mask, pc_before + 1)
                new_pc = pc_before + 1 + skip
                if host_call_id == 100
                    println("      [PC ADVANCE] pc_before=0x$(string(pc_before, base=16)), skip=$skip, new_pc=0x$(string(new_pc, base=16))")
                    if new_pc < length(state.instructions)
                        println("      [NEXT INSTR] opcode at new_pc: 0x$(string(state.instructions[new_pc + 1], base=16))")
                    else
                        println("      [NEXT INSTR] new_pc beyond code! code_len=$(length(state.instructions))")
                    end
                end
                state.pc = new_pc
            end
        else
            # HALT, PANIC, OOG, FAULT - stop execution
            break
        end
    end
    
    # check gas
    if state.gas < 0
        state.status = OOG
    end
    
    # extract output
    output = if state.status == HALT
        extract_output(state)
    else
        UInt8[]
    end

    gas_used = initial_gas - max(state.gas, 0)
    return (state.status, output, gas_used, state.exports)
end

# Overload with context parameter and optional r0 value
# r6_value: for accumulate entry point, this should be the work result count
function execute(program::Vector{UInt8}, input::Vector{UInt8}, gas::UInt64, context, entry_point::Int = 0, r0_value::Union{UInt32, Nothing} = nothing, r6_value::Union{UInt64, Nothing} = nothing)
    result = deblob(program)
    if result === nothing
        return (PANIC, UInt8[], 0, Vector{UInt8}[])
    end

    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

    # Determine starting PC based on entry point
    # Per graypaper Section 14, entry points are direct PC addresses:
    # - 0: is_authorized
    # - 5: accumulate (Ψ_A)
    # - 10: refine (Ψ_R)
    # - 15: on_transfer (Ψ_T)
    # entry point is used directly as PC, not as jump table index
    start_pc = UInt32(entry_point)

    println("  [PVM START] Entry point=$entry_point, start_pc=0x$(string(start_pc, base=16)), jump_table_size=$(length(jump_table)), code_length=$(length(instructions))")

    # Validate start_pc is within code
    if start_pc >= length(instructions)
        println("ERROR: start_pc=0x$(string(start_pc, base=16)) is beyond code length=$(length(instructions))")
        return (PANIC, UInt8[], 0, Vector{UInt8}[])
    end

    # Initialize registers per graypaper Y function (equation \ref{eq:registers})
    # r0 = 2^32 - 2^16 (default) or custom value for specific invocations
    # r1 (SP) = 2^32 - 2*ZONE_SIZE = 0xfffe0000 (per polkavm abi.rs stack_address_high)
    # r7 = 2^32 - ZONE_SIZE - MAX_INPUT (input address)
    # r8 = len(input) (input length)
    # others = 0
    registers = zeros(UInt64, 13)
    if r0_value !== nothing
        # For accumulate, r0 might be timeslot or other context
        registers[1] = UInt64(r0_value)
    else
        registers[1] = UInt64(2^32 - 2^16)  # r0 default
    end
    registers[2] = UInt64(2^32 - 2*ZONE_SIZE - MAX_INPUT)  # r1/SP = 0xfefe0000 per Go ref impl
    # Per graypaper Y function (eq:registers):
    # r7 = 2^32 - ZONE_SIZE - MAX_INPUT (argument pointer)
    # r8 = len(input) (argument length)
    # Per graypaper eq 14.2: accumulate input = encode{s, t, n} (12 bytes)
    # The code reads the count from the input buffer, not from r8
    registers[8] = UInt64(2^32 - ZONE_SIZE - MAX_INPUT)  # r7 = input pointer (a0)
    registers[9] = UInt64(length(input))  # r8 = input length per graypaper

    # Set r6 for accumulate invocation (work result count)
    if r6_value !== nothing
        registers[7] = r6_value  # r6 = work result count (Julia 1-indexed: r6 is registers[7])
    end

    # initialize state
    state = PVMState(
        start_pc,  # pc starts at entry point
        CONTINUE,  # status
        Int64(gas),  # gas
        instructions,  # instructions
        opcode_mask,  # opcode_mask
        precompute_skip_distances(opcode_mask),  # skip_distances
        registers,  # registers with proper initial values
        Memory(),  # memory
        jump_table,  # jump_table
        UInt32(0),  # host_call_id
        Vector{UInt8}[],  # exports
        Dict{UInt32, GuestPVM}()  # machines
    )

    # setup memory layout with program segments
    setup_memory!(state, input, ro_data, rw_data, stack_pages, stack_bytes)

    # run until halt
    initial_gas = state.gas
    invocation_type = :accumulate  # Set to accumulate for accumulate context
    step_count = 0
    max_steps = 100000000  # 100M step limit for safety

    while state.gas > 0 && step_count < max_steps
        # Store step count for debug logging
        task_local_storage(:pvm_step_count, step_count)

        # Debug trace - print every instruction for first 60 steps
        if TRACE_EXECUTION && step_count < 60
            pc_idx = state.pc + 1
            opcode = pc_idx <= length(state.instructions) ? state.instructions[pc_idx] : 0
            # Show all registers for full visibility
            regs = ["r$(i-1)=$(state.registers[i])" for i in 1:13]
            println("    [STEP $step_count] PC=0x$(string(state.pc, base=16, pad=4)) op=0x$(string(opcode, base=16, pad=2))")
            println("      $(join(regs[1:7], " "))")
            println("      $(join(regs[8:13], " "))")

            # For load instructions in critical range, show what's in memory
            if step_count >= 32 && step_count <= 40 && opcode == 0x7b  # load_u32
                # Show memory content at r1 (SP) which is the base for stack loads
                r1 = state.registers[2]  # r1 is SP
                addr = UInt32(r1 % 2^32)
                if addr >= 0x10000 && addr + 64 <= 2^32
                    println("      -> r1(SP)=0x$(string(addr, base=16)), stack contents:")
                    for offset in [0, 8, 16, 24, 48, 56]
                        if addr + offset + 4 <= 2^32
                            val = UInt32(state.memory.data[addr + offset + 1]) |
                                  (UInt32(state.memory.data[addr + offset + 2]) << 8) |
                                  (UInt32(state.memory.data[addr + offset + 3]) << 16) |
                                  (UInt32(state.memory.data[addr + offset + 4]) << 24)
                            println("         [SP+$offset] = 0x$(string(val, base=16, pad=8))")
                        end
                    end
                end
            end
        end
        if state.status == CONTINUE
            step!(state)
            step_count += 1
        elseif state.status == HOST
            # Save PC before host call
            pc_before = state.pc

            # Handle host call with provided context
            host_call_id = Int(state.host_call_id)
            # Log ALL host calls to catch any failures
            # if host_call_id != 1  # Skip FETCH logging (already logged separately)
            #     println("      [HOST CALL] step=$step_count, id=$host_call_id, PC=0x$(string(pc_before, base=16)), r7=$(state.registers[8]), r8=$(state.registers[9]), r9=$(state.registers[10]), r10=$(state.registers[11])")
            # end
            state = HostCalls.dispatch_host_call(host_call_id, state, context, invocation_type)
            # if host_call_id != 1
            #     println("      [HOST CALL AFTER] step=$step_count, id=$host_call_id, status=$(state.status), r7=$(state.registers[8])")
            # end

            # Resume execution if no error
            if state.status == HOST
                state.status = CONTINUE
                # Advance PC past ecalli instruction
                skip = skip_distance(state.opcode_mask, pc_before + 1)
                new_pc = pc_before + 1 + skip
                if host_call_id == 100
                    println("      [PC ADVANCE] pc_before=0x$(string(pc_before, base=16)), skip=$skip, new_pc=0x$(string(new_pc, base=16))")
                    if new_pc < length(state.instructions)
                        println("      [NEXT INSTR] opcode at new_pc: 0x$(string(state.instructions[new_pc + 1], base=16))")
                    else
                        println("      [NEXT INSTR] new_pc beyond code! code_len=$(length(state.instructions))")
                    end
                end
                state.pc = new_pc
            end
        else
            # HALT, PANIC, OOG, FAULT - stop execution
            break
        end

        if step_count == 936
            println("      [END OF ITERATION 936] status=$(state.status), gas=$(state.gas)")
        end
    end

    # check gas
    if state.gas < 0
        state.status = OOG
    end

    # extract output
    output = if state.status == HALT
        extract_output(state)
    else
        UInt8[]
    end

    gas_used = initial_gas - max(state.gas, 0)
    if step_count >= max_steps
        println("WARNING: PVM hit step limit of $max_steps steps")
    end
    if state.status == FAULT
        println("PVM execution FAULTED at PC=0x$(string(state.pc, base=16)), steps=$step_count, gas_used=$gas_used")
    elseif state.status == PANIC
        pc_idx = state.pc + 1
        opcode = pc_idx <= length(state.instructions) ? state.instructions[pc_idx] : 0
        println("PVM execution PANICKED at PC=0x$(string(state.pc, base=16)) opcode=$opcode, steps=$step_count, gas_used=$gas_used")
        # Debug: show register values at panic
        println("  Registers at panic:")
        for i in 0:12
            println("    r$i = 0x$(string(state.registers[i+1], base=16, pad=16))")
        end
    else
        println("PVM execution complete: status=$(state.status), steps=$step_count, gas_used=$gas_used")
    end
    return (state.status, output, gas_used, state.exports)
end

function setup_memory!(state::PVMState, input::Vector{UInt8}, ro_data::Vector{UInt8}, rw_data::Vector{UInt8}, stack_pages::Int, stack_bytes::Int)
    # Memory layout per graypaper Y function (equation 770-801):
    # Zone 0: 0x00000-0x0FFFF (forbidden - first 64KB)
    # ro_data: ZONE_SIZE to ZONE_SIZE + len(o)  [eq 772-775]
    # rw_data: 2*ZONE_SIZE + rnq(len(o)) to 2*ZONE_SIZE + rnq(len(o)) + len(w)  [eq 780-783]
    # Heap: after rw_data
    # Stack: high memory below input
    # Input: 2^32 - ZONE_SIZE - MAX_INPUT
    # NOTE: Code (instructions) is NOT in RAM - it's in state.instructions

    # Helper: round up to next zone boundary (rnq)
    function rnq(x::UInt32)::UInt32
        zone_mask = UInt32(ZONE_SIZE - 1)
        return (x + zone_mask) & ~zone_mask
    end

    # Per graypaper: ro_data at 0x10000, NOT code
    # Code is read from state.instructions, not from memory
    ro_data_start = UInt32(ZONE_SIZE)  # 0x10000
    ro_data_end = ro_data_start + UInt32(length(ro_data))

    # Per graypaper eq for w: rw_data starts at 2*ZONE_SIZE + rnq(len(ro_data))
    # where rnq rounds up to next zone boundary (64KB)
    # This matches polkavm trace showing rw_data at 0x30000 when ro_data is ~13KB
    rw_data_start = UInt32(2 * ZONE_SIZE + rnq(UInt32(length(ro_data))))
    rw_data_end = rw_data_start + UInt32(length(rw_data))

    # Helper: round up to page boundary (rnp)
    function rnp(x::UInt32)::UInt32
        page_mask = UInt32(PAGE_SIZE - 1)
        return (x + page_mask) & ~page_mask
    end

    # Heap starts after rw_data region (with z pages for SBRK)
    heap_start = rw_data_start + rnp(UInt32(length(rw_data))) + UInt32(stack_pages * PAGE_SIZE)
    state.memory.current_heap_pointer = rw_data_start + rnp(UInt32(length(rw_data)))

    # Pre-allocate heap pages (at least one zone)
    heap_prealloc_end = heap_start + UInt32(ZONE_SIZE)

    # println("  [MEM SETUP] ro_data: 0x$(string(ro_data_start, base=16))-0x$(string(ro_data_end-1, base=16)) ($(length(ro_data)) bytes)")
    # println("  [MEM SETUP] rw_data: 0x$(string(rw_data_start, base=16))-0x$(string(rw_data_end-1, base=16)) ($(length(rw_data)) bytes)")
    # println("  [MEM SETUP] heap_ptr: 0x$(string(state.memory.current_heap_pointer, base=16))")
    # println("  [MEM SETUP] stack_pages=$stack_pages, stack_bytes=$stack_bytes")

    # Write ro_data to zone 1 (0x10000+) per graypaper eq 772-775
    for i in 1:length(ro_data)
        state.memory.data[ro_data_start + i] = ro_data[i]
    end

    # Debug: verify write
    # if length(ro_data) > 0x910
    #     for test_offset in [0x900, 0x910, 0x918]
    #         written_addr = UInt32(0x10000 + test_offset)
    #         written_val = state.memory.data[written_addr + 1]  # Fixed: add +1 for 1-indexing
    #         expected_val = ro_data[test_offset + 1]
    #         match_str = written_val == expected_val ? "✓" : "✗ MISMATCH"
    #         println("  [MEM] addr 0x$(string(written_addr, base=16)): wrote=0x$(string(written_val, base=16, pad=2)) expected=0x$(string(expected_val, base=16, pad=2)) $match_str")
    #     end
    # end

    # Write rw_data to zone 2 (0x20000+)
    for i in 1:length(rw_data)
        state.memory.data[rw_data_start + i] = rw_data[i]  # Fixed: was + i - 1, now + i
    end

    # Mark ro_data pages as readable
    # Per graypaper eq 772-779, Zone 1 (0x10000-0x1ffff) is for ro_data
    # Mark ro_data pages as readable
    ro_page_start = div(ro_data_start, PAGE_SIZE)  # Page 16
    ro_page_end = div(ro_data_start + rnp(UInt32(length(ro_data))) - 1, PAGE_SIZE)
    println("  [MEM SETUP] Marking ro_data pages $ro_page_start to $ro_page_end as READ ($(length(ro_data)) bytes)")
    for page in ro_page_start:ro_page_end
        if page + 1 <= length(state.memory.access)
            state.memory.access[page + 1] = READ
        end
    end

    # Mark rw_data + pre-allocated heap pages as writable
    for page in div(rw_data_start, PAGE_SIZE):div(heap_prealloc_end - 1, PAGE_SIZE)
        if page + 1 <= length(state.memory.access)
            state.memory.access[page + 1] = WRITE
        end
    end

    # Input at high memory per graypaper Y function
    input_start = UInt32(2^32 - ZONE_SIZE - MAX_INPUT)
    # println("  [MEM SETUP] input: 0x$(string(input_start, base=16)) ($(length(input)) bytes)")

    # Write input to sparse memory (used by FlatRegion-based read/write)
    for i in 1:min(length(input), MAX_INPUT)
        sparse_write!(state.memory.sparse, input_start + UInt32(i - 1), input[i])
    end

    # Mark input/output pages as writable (program reads input and writes output here)
    for page in div(input_start, PAGE_SIZE):div(input_start + length(input), PAGE_SIZE)
        state.memory.access[page + 1] = WRITE
    end

    # Stack region: per Go ref impl, SP = 2^32 - 2*Z_Z - Z_I = 0xfefe0000
    stack_top = UInt32(UInt64(2^32) - UInt64(2)*UInt64(ZONE_SIZE) - UInt64(MAX_INPUT))  # 0xfefe0000
    stack_bottom = stack_top - UInt32(max(stack_bytes, 1024 * 1024))  # Use actual stack size or 1MB min
    # println("  [MEM SETUP] stack: 0x$(string(stack_bottom, base=16))-0x$(string(stack_top, base=16))")

    for page in div(stack_bottom, PAGE_SIZE):div(stack_top, PAGE_SIZE)
        state.memory.access[page + 1] = WRITE
    end

    # Initialize the FlatRegion-based memory system (used by optimized read/write paths)
    ro_size = rnp(UInt32(length(ro_data)))
    # RW region needs to extend at least one zone beyond data for BSS
    rw_size = max(rnp(UInt32(length(rw_data))), UInt32(ZONE_SIZE))
    init_memory_regions!(state.memory,
        ro_data_start, ro_size, ro_data,
        rw_data_start, rw_size, rw_data,
        stack_bottom, stack_top,
        heap_start, stack_bottom)  # heap_limit is where stack begins

    # Set up stack frame for polkavm ABI compatibility
    # The test-service's prologue loads saved registers from the stack.
    args_segment = UInt32(2^32 - ZONE_SIZE - MAX_INPUT)  # 0xfeff0000 (input pointer)

    # Helper to write 8-byte value to stack
    function write_u64_to_stack(sp::UInt32, offset::Int, value::UInt64)
        for i in 0:7
            state.memory.data[sp + offset + i + 1] = UInt8((value >> (8 * i)) & 0xff)
        end
    end

    sp_addr = stack_top  # 0xfefe0000
    scratch = UInt32(sp_addr - 0x100)  # Writable area below SP

    # Populate saved register slots on stack per polkavm calling convention
    write_u64_to_stack(sp_addr, 0, UInt64(args_segment))    # [SP+0] -> r7 (input ptr)
    write_u64_to_stack(sp_addr, 8, UInt64(scratch))         # [SP+8] -> r9 (scratch area)
    write_u64_to_stack(sp_addr, 16, UInt64(0))              # [SP+16] -> count/flags (0 for direct entry)
    write_u64_to_stack(sp_addr, 24, UInt64(scratch + 64))   # [SP+24] -> scratch area 2
    write_u64_to_stack(sp_addr, 32, UInt64(0))              # [SP+32] -> r6
    write_u64_to_stack(sp_addr, 40, UInt64(0))              # [SP+40] -> r5
    write_u64_to_stack(sp_addr, 48, UInt64(0xFFFF0000))     # [SP+48] -> r0 (return to host)
    write_u64_to_stack(sp_addr, 56, UInt64(0))              # [SP+56] -> padding
end

function extract_output(state::PVMState)
    output_ptr = state.registers[8]
    output_len = state.registers[9]

    # Bounds check
    if output_len > MAX_INPUT || output_len == 0
        return UInt8[]
    end

    if output_ptr + output_len > UInt64(2^32)
        return UInt8[]
    end

    output = UInt8[]
    for i in 0:output_len-1
        addr = output_ptr + i
        page = div(addr, PAGE_SIZE)

        # Check page access
        access = get(state.memory.access, page + 1, NONE)
        if access != READ && access != WRITE
            return UInt8[]
        end
        push!(output, state.memory.data[addr + 1])
    end

    return output
end

export execute, PVMState, Memory, HALT, PANIC, OOG, FAULT, HOST, CONTINUE
export step!, init_memory_regions!, precompute_skip_distances, skip_distance

end # module PVM
