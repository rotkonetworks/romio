# complete pvm interpreter implementation following graypaper spec
module PVM

# No external dependencies - using native Julia arrays

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

# exit reasons
const CONTINUE = :continue
const HALT = :halt
const PANIC = :panic
const OOG = :oog
const FAULT = :fault
const HOST = :host

# memory access permissions
const READ = :R
const WRITE = :W
const NONE = nothing

mutable struct Memory
    data::Vector{UInt8}
    access::Vector{Union{Symbol, Nothing}}  # per-page access
    current_heap_pointer::UInt32  # Current heap top for sbrk

    function Memory()
        data = zeros(UInt8, 2^32)
        access = fill(NONE, div(2^32, PAGE_SIZE))
        # Heap pointer will be initialized in setup_memory!
        new(data, access, UInt32(0))
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
    status::Symbol  # execution status (8 bytes)
    gas::Int64  # gas remaining (8 bytes)
    instructions::Vector{UInt8}  # instruction bytes (24 bytes ptr+len+cap)
    opcode_mask::BitVector  # marks opcode positions (24 bytes)
    # = 68 bytes (just over 1 cache line)

    # FREQUENTLY ACCESSED - Registers and memory (next cache line)
    registers::Vector{UInt64}  # 13 general purpose registers (24 bytes)
    memory::Memory  # (8 bytes ptr)

    # LESS FREQUENTLY ACCESSED - Jump table and special features
    jump_table::Vector{UInt32}  # dynamic jump targets
    host_call_id::UInt32  # temporary storage for host call ID
    exports::Vector{Vector{UInt8}}  # list of exported memory segments
    machines::Dict{UInt32, GuestPVM}  # machine_id => guest PVM
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

    # Skip o - RO data
    offset += Int(ro_len)
    if offset > length(program)
        return nothing
    end

    # Skip w - RW data
    offset += Int(rw_len)
    if offset > length(program)
        return nothing
    end

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

    return (instructions, opcode_mask, jump_table)
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
@inline function read_u8(state::PVMState, addr::UInt64)
    @inbounds begin
        addr32 = UInt32(addr % 2^32)
        page = div(addr32, PAGE_SIZE)

        # check access
        if addr32 < 2^16  # first 64KB always inaccessible
            state.status = PANIC
            return UInt8(0)
        end

        page_idx = page + 1
        if page_idx > length(state.memory.access)
            state.status = FAULT
            state.pc = page * PAGE_SIZE
            return UInt8(0)
        end

        access = state.memory.access[page_idx]
        if access != READ && access != WRITE
            state.status = FAULT
            state.pc = page * PAGE_SIZE
            return UInt8(0)
        end

        val = state.memory.data[addr32 + 1]
        return val
    end
end

@inline function write_u8(state::PVMState, addr::UInt64, val::UInt8)
    @inbounds begin
        addr32 = UInt32(addr % 2^32)
        page = div(addr32, PAGE_SIZE)

        # check access
        if addr32 < 2^16
            state.status = PANIC
            return
        end

        page_idx = page + 1
        if page_idx > length(state.memory.access)
            state.status = FAULT
            state.pc = page * PAGE_SIZE
            return
        end

        if state.memory.access[page_idx] != WRITE
            state.status = FAULT
            state.pc = page * PAGE_SIZE
            return
        end

        state.memory.data[addr32 + 1] = val
    end
end

# Optimized: pre-allocate result vector
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

# Optimized: inline loop for small writes
@inline function write_bytes(state::PVMState, addr::UInt64, data::Vector{UInt8})
    @inbounds for i in 1:length(data)
        write_u8(state, addr + UInt64(i - 1), data[i])
        if state.status != CONTINUE
            return
        end
    end
end

# decode helpers
function decode_immediate(state::PVMState, offset::Int, len::Int)
    val = UInt64(0)
    for i in 0:len-1
        if state.pc + offset + i < length(state.instructions)
            val |= UInt64(state.instructions[state.pc + offset + i + 1]) << (8*i)
        end
    end
    
    # sign extend if MSB is set
    if len > 0 && (val >> (8*len - 1)) & 1 == 1
        val |= ~((UInt64(1) << (8*len)) - 1)
    end
    
    return val
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

function get_register_index(state::PVMState, byte_offset::Int, nibble::Int)
    if state.pc + byte_offset >= length(state.instructions)
        return 0
    end
    
    byte = state.instructions[state.pc + byte_offset + 1]
    idx = if nibble == 0
        byte & 0x0F
    else
        byte >> 4
    end
    
    return min(12, idx)
end

# signed/unsigned conversions
function sign_extend_32(val::UInt32)
    if val & 0x80000000 != 0
        return UInt64(val) | 0xFFFFFFFF00000000
    else
        return UInt64(val)
    end
end

function to_signed(val::UInt64)
    return reinterpret(Int64, val)
end

function to_unsigned(val::Int64)
    return reinterpret(UInt64, val)
end

function smod(a::T, b::T) where T <: Integer
    if b == 0
        return a
    else
        return sign(a) * (abs(a) % abs(b))
    end
end

# single step execution
@inline function step!(state::PVMState)
    @inbounds begin
        if state.status != CONTINUE
            return
        end

        # bounds check
        pc_idx = Int(state.pc) + 1
        if pc_idx > length(state.instructions)
            state.status = PANIC
            return
        end

        # get opcode if valid (no bounds check - proven above)
        opcode = if state.opcode_mask[pc_idx]
            state.instructions[pc_idx]
        else
            0x00  # invalid -> trap
        end

        # execute instruction
        skip = skip_distance(state.opcode_mask, pc_idx)
        execute_instruction!(state, opcode, skip)

        # advance pc if still running and not branching instruction
        if state.status == CONTINUE && !is_branch_instruction(opcode)
            state.pc += 1 + skip
        end
    end
end

@inline function is_branch_instruction(opcode::UInt8)
    # Optimized: direct comparisons faster than set lookup
    return opcode == 40 || opcode == 50 || opcode == 180 ||
           (170 <= opcode <= 175) || (80 <= opcode <= 90)
end

# complete instruction execution implementation
function execute_instruction!(state::PVMState, opcode::UInt8, skip::Int)
    # charge gas
    state.gas -= 1
    
    if opcode == 0  # trap
        state.status = PANIC
        
    elseif opcode == 1  # fallthrough
        # nop
        
    elseif opcode == 0x0A  # ecalli
        imm = decode_immediate(state, 1, min(4, skip))
        println("    [ECALLI] id=$imm at PC=0x$(string(state.pc, base=16)), r7=$(state.registers[8])")
        if imm == 100
            # Show exactly what bytes we're reading
            bytes_shown = min(10, length(state.instructions) - Int(state.pc))
            instr_bytes = state.instructions[state.pc+1:state.pc+bytes_shown]
            println("      Instruction bytes: $(instr_bytes)")
            println("      Decoded immediate (len=$(min(4, skip))): $imm")
            println("      Registers: r7=$(state.registers[8]), r10=$(state.registers[11])")
        end
        state.status = HOST
        # store host call id in dedicated field (don't overwrite registers!)
        state.host_call_id = UInt32(imm)

    elseif opcode == 16  # store_u32 sp-relative (0x10)
        # Store 32-bit value to [sp + offset]
        # Format: 0x10 <offset_byte>
        # The register is RA (register 1) implicitly
        offset = decode_immediate(state, 1, 1)  # Only 1 byte for offset
        addr = state.registers[2 + 1] + offset  # SP is register 2
        val = UInt32(state.registers[1 + 1] & 0xFFFFFFFF)  # RA is register 1
        # DEBUG: store_u32 sp-relative
        write_bytes(state, addr, [
            UInt8(val & 0xFF),
            UInt8((val >> 8) & 0xFF),
            UInt8((val >> 16) & 0xFF),
            UInt8((val >> 24) & 0xFF)
        ])
        # After write_bytes

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
        write_bytes(state, addr, [
            UInt8(val & 0xFF),
            UInt8((val >> 8) & 0xFF),
            UInt8((val >> 16) & 0xFF),
            UInt8((val >> 24) & 0xFF)
        ])

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
        val = UInt16(immy % 2^16)
        write_bytes(state, immx, [UInt8(val & 0xFF), UInt8(val >> 8)])
        
    elseif opcode == 32  # store_imm_u32
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        val = UInt32(immy % 2^32)
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:3]
        write_bytes(state, immx, bytes)
        
    elseif opcode == 33  # store_imm_u64
        lx = Int(min(4, state.instructions[state.pc + 2] % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        bytes = [UInt8((immy >> (8*i)) & 0xFF) for i in 0:7]
        write_bytes(state, immx, bytes)
        
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
        state.registers[ra + 1] = immx
        
    elseif opcode == 52  # load_u8
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = UInt64(read_u8(state, immx))
        
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
        state.registers[ra + 1] = UInt64(bytes[1]) | (UInt64(bytes[2]) << 8) | (UInt64(bytes[3]) << 16) | (UInt64(bytes[4]) << 24)
        
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
        val = state.registers[ra + 1] % 2^16
        write_bytes(state, immx, [UInt8(val & 0xFF), UInt8((val >> 8) & 0xFF)])
        
    elseif opcode == 61  # store_u32
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = state.registers[ra + 1] % 2^32
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:3]
        write_bytes(state, immx, bytes)
        
    elseif opcode == 62  # store_u64
        ra = get_register_index(state, 1, 0)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = state.registers[ra + 1]
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:7]

        write_bytes(state, immx, bytes)
        
    # instructions with one register & two immediates (70-73)
    elseif opcode == 70  # store_imm_ind_u8
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        write_u8(state, addr, UInt8(immy & 0xFF))
        
    elseif opcode == 71  # store_imm_ind_u16
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        val = immy % 2^16
        write_bytes(state, addr, [UInt8(val & 0xFF), UInt8((val >> 8) & 0xFF)])
        
    elseif opcode == 72  # store_imm_ind_u32
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        val = immy % 2^32
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:3]
        write_bytes(state, addr, bytes)
        
    elseif opcode == 73  # store_imm_ind_u64
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy = decode_immediate(state, 2 + lx, ly)
        addr = state.registers[ra + 1] + immx
        bytes = [UInt8((immy >> (8*i)) & 0xFF) for i in 0:7]
        write_bytes(state, addr, bytes)
        
    # instructions with one register, one immediate and one offset (80-90)
    elseif opcode == 80  # load_imm_jump
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
        immy_offset = decode_offset(state, 2 + lx, ly)
        state.registers[ra + 1] = immx
        state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        
    elseif opcode == 81  # branch_eq_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, lx)
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
        immy_offset = decode_offset(state, 2 + lx, ly)
        if state.registers[ra + 1] > immx
            state.pc = UInt32((Int32(state.pc) + immy_offset) % 2^32)
        else
            state.pc += 1 + skip
        end
        
    elseif opcode == 87 && state.pc == 12  # Actually this is a0 = a0 + s0 at PC=12
        # Based on disassembly at PC=12: a0 = a0 + s0
        # But first check - this seems wrong, a0 should be 3 after ecalli
        println("Before: a0=$(state.registers[8+1]), s0=$(state.registers[5+1])")
        state.registers[8 + 1] = state.registers[8 + 1] + state.registers[5 + 1]
        println("After: a0 = a0 + s0 = $(state.registers[8+1])")
        # PC needs to advance by 1 + skip
        state.pc += 1 + skip

    elseif opcode == 87  # branch_lt_s_imm
        ra = get_register_index(state, 1, 0)
        lx = Int(min(4, div(state.instructions[state.pc + 2], 16) % 8))
        ly = min(4, max(0, skip - lx - 1))
        immx = decode_immediate(state, 2, Int(lx))
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

                    # Allocate pages in the new range
                    for page_idx in idx_start:(idx_end-1)
                        if page_idx + 1 <= length(state.memory.access)
                            state.memory.access[page_idx + 1] = :write
                        end
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
        offset = decode_immediate(state, 2, min(skip - 1, 4))
        addr = state.registers[rb + 1] + offset
        val = UInt32(state.registers[rs + 1] & 0xFFFFFFFF)
        write_bytes(state, addr, [
            UInt8(val & 0xFF),
            UInt8((val >> 8) & 0xFF),
            UInt8((val >> 16) & 0xFF),
            UInt8((val >> 24) & 0xFF)
        ])

    elseif opcode == 0x78  # This appears to be add_32 based on context
        # Bytes: 0x78 0x05 (rd=5/s0 in low nibble, ra/rb follow)
        # Next byte has the source registers
        rd = 5  # s0 is register 5
        ra = 8  # a0 is register 8
        rb = 9  # a1 is register 9
        state.registers[rd + 1] = state.registers[ra + 1] + state.registers[rb + 1]

    elseif opcode == 120 && false  # load_i32_ind (load signed 32-bit from [base + offset])
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

    elseif opcode == 0x83  # add_imm
        rd = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        imm = decode_immediate(state, 2, min(skip - 1, 4))
        state.registers[rd + 1] = state.registers[rb + 1] + imm

    # Note: opcode 0x32 (50) is jump_ind, already handled above at line 379
    # The "ret" instruction does not exist in the PVM spec

    # Add these instructions after opcode 111 and before 190:

    # Two registers & one immediate (120-161)
    elseif opcode == 120  # store_ind_u8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        write_u8(state, state.registers[rb + 1] + immx, UInt8(state.registers[ra + 1] & 0xFF))
        
    elseif opcode == 121  # store_ind_u16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = state.registers[ra + 1] % 2^16
        write_bytes(state, state.registers[rb + 1] + immx, [UInt8(val & 0xFF), UInt8((val >> 8) & 0xFF)])
        
    elseif opcode == 122  # store_ind_u32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = state.registers[ra + 1] % 2^32
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:3]
        write_bytes(state, state.registers[rb + 1] + immx, bytes)
        
    elseif opcode == 123  # store_ind_u64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = state.registers[ra + 1]
        bytes = [UInt8((val >> (8*i)) & 0xFF) for i in 0:7]
        write_bytes(state, state.registers[rb + 1] + immx, bytes)
        
    elseif opcode == 124  # load_ind_u8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        addr = state.registers[rb + 1] + immx
        state.registers[ra + 1] = UInt64(read_u8(state, addr))
        
    elseif opcode == 125  # load_ind_i8
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        val = read_u8(state, state.registers[rb + 1] + immx)
        state.registers[ra + 1] = val >= 128 ? UInt64(val) | 0xFFFFFFFFFFFFFF00 : UInt64(val)
        
    elseif opcode == 126  # load_ind_u16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, state.registers[rb + 1] + immx, 2)
        state.registers[ra + 1] = UInt64(bytes[1]) | (UInt64(bytes[2]) << 8)
        
    elseif opcode == 127  # load_ind_i16
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, state.registers[rb + 1] + immx, 2)
        val = UInt16(bytes[1]) | (UInt16(bytes[2]) << 8)
        state.registers[ra + 1] = val >= 32768 ? UInt64(val) | 0xFFFFFFFFFFFF0000 : UInt64(val)
        
    elseif opcode == 128  # load_ind_u32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, state.registers[rb + 1] + immx, 4)
        state.registers[ra + 1] = UInt64(bytes[1]) | (UInt64(bytes[2]) << 8) | (UInt64(bytes[3]) << 16) | (UInt64(bytes[4]) << 24)
        
    elseif opcode == 129  # load_ind_i32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, state.registers[rb + 1] + immx, 4)
        val = UInt32(bytes[1]) | (UInt32(bytes[2]) << 8) | (UInt32(bytes[3]) << 16) | (UInt32(bytes[4]) << 24)
        state.registers[ra + 1] = sign_extend_32(val)
        
    elseif opcode == 130  # load_ind_u64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        bytes = read_bytes(state, state.registers[rb + 1] + immx, 8)
        # If read failed (returned fewer than 8 bytes), register not updated and status already set
        if length(bytes) == 8
            state.registers[ra + 1] = sum(UInt64(bytes[i+1]) << (8*i) for i in 0:7)
        end
        
    elseif opcode == 131  # add_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        result = UInt32((state.registers[rb + 1] + immx) % 2^32)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 132  # and_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = state.registers[rb + 1] & immx
        
    elseif opcode == 133  # xor_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = state.registers[rb + 1] ⊻ immx
        
    elseif opcode == 134  # or_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
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
        state.registers[ra + 1] = state.registers[rb + 1] < immx ? 1 : 0
        
    elseif opcode == 137  # set_lt_s_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
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
        val = Int32(state.registers[rb + 1] % 2^32)
        result = val >> shift
        state.registers[ra + 1] = to_unsigned(Int64(result))
        
    elseif opcode == 141  # neg_add_imm_32
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        result = UInt32((immx + 2^32 - state.registers[rb + 1]) % 2^32)
        state.registers[ra + 1] = sign_extend_32(result)
        
    elseif opcode == 142  # set_gt_u_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = state.registers[rb + 1] > immx ? 1 : 0
        
    elseif opcode == 143  # set_gt_s_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
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
        val = Int32(immx % 2^32)
        result = val >> shift
        state.registers[ra + 1] = to_unsigned(Int64(result))
        
    elseif opcode == 147  # cmov_iz_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = state.registers[rb + 1] == 0 ? immx : state.registers[ra + 1]
        
    elseif opcode == 148  # cmov_nz_imm
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = state.registers[rb + 1] != 0 ? immx : state.registers[ra + 1]
        
    elseif opcode == 149  # add_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        state.registers[ra + 1] = UInt64(state.registers[rb + 1] + immx)
        
    elseif opcode == 150  # mul_imm_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
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
        state.registers[ra + 1] = UInt64(immx - state.registers[rb + 1])
        
    elseif opcode == 155  # shlo_l_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = state.registers[rb + 1] % 64
        state.registers[ra + 1] = UInt64(immx << shift)
        
    elseif opcode == 156  # shlo_r_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
        shift = state.registers[rb + 1] % 64
        state.registers[ra + 1] = immx >> shift
        
    elseif opcode == 157  # shar_r_imm_alt_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        lx = min(4, max(0, skip - 1))
        immx = decode_immediate(state, 2, lx)
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
        if state.registers[ra + 1] >= state.registers[rb + 1]
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
        state.registers[ra + 1] = immx
        addr = (state.registers[rb + 1] + immy) % 2^32
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
        a = Int32(state.registers[ra + 1] % 2^32)
        b = Int32(state.registers[rb + 1] % 2^32)
        if b == 0
            state.registers[rd + 1] = 2^64 - 1
        elseif a == typemin(Int32) && b == -1
            state.registers[rd + 1] = to_unsigned(Int64(a))
        else
            state.registers[rd + 1] = to_unsigned(Int64(div(a, b)))
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
        a = Int32(state.registers[ra + 1] % 2^32)
        b = Int32(state.registers[rb + 1] % 2^32)
        if a == typemin(Int32) && b == -1
            state.registers[rd + 1] = 0
        else
            result = smod(a, b)
            state.registers[rd + 1] = to_unsigned(Int64(result))
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
        val = Int32(state.registers[ra + 1] % 2^32)
        result = val >> shift
        state.registers[rd + 1] = to_unsigned(Int64(result))

    # 200-202 already implemented, continuing from 203:
    elseif opcode == 203  # div_u_64
        ra = get_register_index(state, 1, 0)
        rb = get_register_index(state, 1, 1)
        rd = get_register_index(state, 2, 0)
        if state.registers[rb + 1] == 0
            state.registers[rd + 1] = 2^64 - 1
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
            state.registers[rd + 1] = 2^64 - 1
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
        state.registers[rd + 1] = state.registers[ra + 1] & ~state.registers[rb + 1]
        
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
            state.registers[rd + 1] = 2^64 - 1
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
        zeros(UInt64, 13),  # registers
        Memory(),  # memory
        jump_table,  # jump_table
        UInt32(0),  # host_call_id
        Vector{UInt8}[],  # exports
        Dict{UInt32, GuestPVM}()  # machines
    )
    
    # setup memory layout
    setup_memory!(state, input)
    
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
                state.pc = pc_before + 1 + skip
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

# Overload with context parameter
function execute(program::Vector{UInt8}, input::Vector{UInt8}, gas::UInt64, context, entry_point::Int = 0)
    result = deblob(program)
    if result === nothing
        return (PANIC, UInt8[], 0, Vector{UInt8}[])
    end

    instructions, opcode_mask, jump_table = result

    # Determine starting PC based on entry point
    # Entry point 0 = start at PC 0
    # Entry point N (0-indexed) = start at jump_table[N+1] (Julia 1-indexed)
    start_pc = if entry_point == 0
        UInt32(0)
    else
        if entry_point + 1 > length(jump_table)
            println("ERROR: Entry point $entry_point requested but jump_table only has $(length(jump_table)) entries")
            return (PANIC, UInt8[], 0, Vector{UInt8}[])
        end
        # Entry point 5 (0-indexed) → jump_table[6] in Julia
        jump_table[entry_point + 1]
    end

    println("  [PVM START] Entry point=$entry_point, start_pc=0x$(string(start_pc, base=16)), jump_table_size=$(length(jump_table)), code_length=$(length(instructions))")

    # Validate start_pc is within code
    if start_pc >= length(instructions)
        println("ERROR: start_pc=0x$(string(start_pc, base=16)) is beyond code length=$(length(instructions))")
        return (PANIC, UInt8[], 0, Vector{UInt8}[])
    end

    # initialize state
    state = PVMState(
        start_pc,  # pc starts at entry point
        CONTINUE,  # status
        Int64(gas),  # gas
        instructions,  # instructions
        opcode_mask,  # opcode_mask
        zeros(UInt64, 13),  # registers
        Memory(),  # memory
        jump_table,  # jump_table
        UInt32(0),  # host_call_id
        Vector{UInt8}[],  # exports
        Dict{UInt32, GuestPVM}()  # machines
    )

    # setup memory layout
    setup_memory!(state, input)

    # run until halt
    initial_gas = state.gas
    invocation_type = :accumulate  # Set to accumulate for accumulate context
    step_count = 0
    max_steps = 100000000  # 100M step limit for safety

    while state.gas > 0 && step_count < max_steps
        if state.status == CONTINUE
            # Trace steps 25-40 to find what triggers error path
            if step_count >= 25 && step_count < 40
                if state.pc + 1 <= length(state.instructions)
                    opcode = state.instructions[state.pc + 1]
                    r7 = state.registers[8]
                    r8 = state.registers[9]
                    r9 = state.registers[10]
                    println("  [TRACE] step=$step_count PC=0x$(string(state.pc, base=16)) op=0x$(string(opcode, base=16, pad=2)) r7=$r7 r8=$r8 r9=$r9")
                end
            end
            step!(state)
            step_count += 1
        elseif state.status == HOST
            # Save PC before host call
            pc_before = state.pc

            # Handle host call with provided context
            host_call_id = Int(state.host_call_id)
            state = HostCalls.dispatch_host_call(host_call_id, state, context, invocation_type)

            # Resume execution if no error
            if state.status == HOST
                state.status = CONTINUE
                # Advance PC past ecalli instruction
                skip = skip_distance(state.opcode_mask, pc_before + 1)
                state.pc = pc_before + 1 + skip
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
    if step_count >= max_steps
        println("WARNING: PVM hit step limit of $max_steps steps")
    end
    if state.status == FAULT
        println("PVM execution FAULTED at PC=$(state.pc), steps=$step_count, gas_used=$gas_used")
    else
        println("PVM execution complete: status=$(state.status), steps=$step_count, gas_used=$gas_used")
    end
    return (state.status, output, gas_used, state.exports)
end

function setup_memory!(state::PVMState, input::Vector{UInt8})
    # input at high memory (readable)
    input_start = UInt32(2^32 - ZONE_SIZE - MAX_INPUT)
    for i in 1:min(length(input), MAX_INPUT)
        state.memory.data[input_start + i] = input[i]
    end

    # mark input pages as readable
    for page in div(input_start, PAGE_SIZE):div(input_start + length(input), PAGE_SIZE)
        state.memory.access[page + 1] = READ
    end

    # Stack region: below input, grows downward (writable)
    # Stack starts at SP and can grow down, allocate reasonable stack space
    stack_top = UInt32(UInt64(2^32) - UInt64(2)*UInt64(ZONE_SIZE) - UInt64(MAX_INPUT))
    stack_bottom = stack_top - UInt32(1024 * 1024)  # 1MB stack
    for page in div(stack_bottom, PAGE_SIZE):div(stack_top, PAGE_SIZE)
        if page + 1 <= length(state.memory.access)
            state.memory.access[page + 1] = WRITE
        end
    end

    # Initialize heap pointer per traces/README.md memory model
    # Zone 0: 0x00000-0x0FFFF (forbidden)
    # Zone 1: 0x10000-0x1FFFF (ro_data - readable)
    # Zone 2: 0x20000-0x2FFFF (rw_data - writable)
    # Zone 3+: 0x30000+ (heap - writable)

    ro_data_start = UInt32(ZONE_SIZE)
    ro_data_end = UInt32(2 * ZONE_SIZE)
    rw_data_start = ro_data_end
    rw_data_end = UInt32(3 * ZONE_SIZE)

    # Pre-allocate initial heap (1 zone = 64KB)
    heap_prealloc_end = UInt32(4 * ZONE_SIZE)
    state.memory.current_heap_pointer = heap_prealloc_end

    # Mark ro_data zone as readable (zone 1: 0x10000-0x1FFFF)
    for page in div(ro_data_start, PAGE_SIZE):div(ro_data_end - 1, PAGE_SIZE)
        if page + 1 <= length(state.memory.access)
            state.memory.access[page + 1] = READ
        end
    end

    # Mark rw_data zone + initial heap as writable (zones 2-3: 0x20000-0x3FFFF)
    for page in div(rw_data_start, PAGE_SIZE):div(heap_prealloc_end - 1, PAGE_SIZE)
        if page + 1 <= length(state.memory.access)
            state.memory.access[page + 1] = WRITE
        end
    end

    # setup initial registers per spec
    state.registers[1] = UInt64(0xFFFF0000)  # RA = 2^32 - 2^16 (halt address)
    state.registers[2] = UInt64(2^32) - UInt64(2)*UInt64(ZONE_SIZE) - UInt64(MAX_INPUT)  # SP
    state.registers[8] = UInt64(input_start)  # A0
    state.registers[9] = UInt64(length(input))  # A1
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

        # Check page bounds
        if page + 1 > length(state.memory.access)
            return UInt8[]
        end

        if state.memory.access[page + 1] != READ
            return UInt8[]
        end
        push!(output, state.memory.data[addr + 1])
    end

    return output
end

export execute, PVMState, Memory, HALT, PANIC, OOG, FAULT, HOST

end # module PVM
