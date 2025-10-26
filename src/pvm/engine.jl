# Complete PVM execution engine

include("../types/basic.jl")

# PVM register type (64-bit)
const PvmReg = UInt64

# PVM exit reasons
@enum PvmExitReason begin
    HALT = 1
    PANIC = 2
    OUT_OF_GAS = 3
    FAULT = 4  # with address
    HOST_CALL = 5  # with call ID
end

# PVM exit result
struct PvmExit
    reason::PvmExitReason
    data::UInt64  # fault address or host call ID
end

# PVM memory page (4KB pages)
const PVM_PAGE_SIZE = 4096
const PVM_PROTECTED_MEMORY = 65536  # First 64KB protected

mutable struct PvmMemory
    pages::Dict{UInt32, Vector{UInt8}}  # page_number -> page_data
    readable_pages::Set{UInt32}
    writable_pages::Set{UInt32}
end

function PvmMemory()
    PvmMemory(
        Dict{UInt32, Vector{UInt8}}(),
        Set{UInt32}(),
        Set{UInt32}()
    )
end

# PVM machine state
mutable struct PvmState
    # Registers (13 registers: RA, SP, T0-T2, S0-S1, A0-A5)
    registers::Vector{PvmReg}

    # Memory
    memory::PvmMemory

    # Program counter
    pc::UInt32

    # Gas counter
    gas::Int64

    # Program blob components
    instructions::Vector{UInt8}
    opcode_mask::Vector{Bool}
    jump_table::Vector{UInt32}
end

function PvmState()
    PvmState(
        zeros(PvmReg, 13),  # 13 registers
        PvmMemory(),
        0,  # start at PC 0
        0,  # no gas initially
        Vector{UInt8}(),
        Vector{Bool}(),
        Vector{UInt32}()
    )
end

# Decode program blob
function decode_program_blob(blob::Vector{UInt8})::Tuple{Vector{UInt8}, Vector{Bool}, Vector{UInt32}}
    if length(blob) < 4
        throw(ArgumentError("Invalid program blob"))
    end

    offset = 1

    # Read jump table length
    jump_table_len = reinterpret(UInt32, blob[offset:offset+3])[1]
    offset += 4

    # Read jump table entry size
    if offset > length(blob)
        throw(ArgumentError("Invalid program blob"))
    end
    entry_size = blob[offset]
    offset += 1

    # Read instruction length
    if offset + 3 > length(blob)
        throw(ArgumentError("Invalid program blob"))
    end
    instr_len = reinterpret(UInt32, blob[offset:offset+3])[1]
    offset += 4

    # Read jump table
    jump_table = Vector{UInt32}()
    for i in 1:jump_table_len
        if offset + entry_size - 1 > length(blob)
            throw(ArgumentError("Invalid program blob"))
        end

        # Read jump target (little-endian)
        target = UInt32(0)
        for j in 1:entry_size
            target |= UInt32(blob[offset]) << (8 * (j - 1))
            offset += 1
        end
        push!(jump_table, target)
    end

    # Read instructions
    if offset + instr_len - 1 > length(blob)
        throw(ArgumentError("Invalid program blob"))
    end
    instructions = blob[offset:offset+instr_len-1]
    offset += instr_len

    # Read opcode mask
    if offset + instr_len - 1 > length(blob)
        throw(ArgumentError("Invalid program blob"))
    end
    mask_bytes = blob[offset:offset+instr_len-1]
    opcode_mask = [b != 0 for b in mask_bytes]

    return (instructions, opcode_mask, jump_table)
end

# Skip function - find next instruction
function skip_distance(opcode_mask::Vector{Bool}, pc::UInt32)::UInt32
    # Look for next set bit in mask
    for i in 1:min(24, length(opcode_mask) - pc)
        if pc + i <= length(opcode_mask) && opcode_mask[pc + i]
            return i - 1
        end
    end
    return min(24, length(opcode_mask) - pc)
end

# Memory access functions
function read_memory(memory::PvmMemory, address::UInt64, size::Int)::Union{Vector{UInt8}, Symbol}
    # Check for protected memory access
    if address < PVM_PROTECTED_MEMORY
        return :panic
    end

    result = Vector{UInt8}()

    for i in 0:size-1
        addr = address + i
        page_num = UInt32(addr ÷ PVM_PAGE_SIZE)
        page_offset = addr % PVM_PAGE_SIZE

        # Check if page is readable
        if page_num ∉ memory.readable_pages
            return :fault
        end

        # Get page data
        if haskey(memory.pages, page_num)
            page = memory.pages[page_num]
            if page_offset < length(page)
                push!(result, page[page_offset + 1])
            else
                push!(result, 0)
            end
        else
            push!(result, 0)
        end
    end

    return result
end

function write_memory!(memory::PvmMemory, address::UInt64, data::Vector{UInt8})::Union{Bool, Symbol}
    # Check for protected memory access
    if address < PVM_PROTECTED_MEMORY
        return :panic
    end

    for (i, byte) in enumerate(data)
        addr = address + i - 1
        page_num = UInt32(addr ÷ PVM_PAGE_SIZE)
        page_offset = addr % PVM_PAGE_SIZE

        # Check if page is writable
        if page_num ∉ memory.writable_pages
            return :fault
        end

        # Get or create page
        if !haskey(memory.pages, page_num)
            memory.pages[page_num] = zeros(UInt8, PVM_PAGE_SIZE)
        end

        memory.pages[page_num][page_offset + 1] = byte
    end

    return true
end

# Load immediate value with sign extension
function load_immediate(instructions::Vector{UInt8}, pc::UInt32, size::Int)::PvmReg
    value = UInt64(0)

    # Read little-endian value
    for i in 0:size-1
        if pc + 1 + i <= length(instructions)
            value |= UInt64(instructions[pc + 1 + i]) << (8 * i)
        end
    end

    # Sign extend if MSB is set
    if size > 0 && size < 8
        msb = 1 << (8 * size - 1)
        if (value & msb) != 0
            # Sign extend
            mask = ~UInt64(0) << (8 * size)
            value |= mask
        end
    end

    return value
end

# Instruction gas costs
const INSTRUCTION_GAS = Dict{UInt8, Int64}(
    0x00 => 1,   # trap
    0x01 => 1,   # fallthrough
    0x02 => 2,   # load_imm
    0x03 => 3,   # load_u8
    0x04 => 3,   # load_u16
    0x05 => 3,   # load_u32
    0x06 => 3,   # load_u64
    0x07 => 3,   # store_u8
    0x08 => 3,   # store_u16
    0x09 => 3,   # store_u32
    0x0a => 3,   # store_u64
    0x0b => 2,   # jump
    # ... more instructions
)

# Execute single instruction
function execute_instruction(state::PvmState)::PvmExit
    if state.pc >= length(state.instructions)
        return PvmExit(PANIC, 0)
    end

    # Check if this is a valid instruction start
    if state.pc + 1 > length(state.opcode_mask) || !state.opcode_mask[state.pc + 1]
        return PvmExit(PANIC, 0)
    end

    opcode = state.instructions[state.pc + 1]

    # Calculate gas cost
    gas_cost = get(INSTRUCTION_GAS, opcode, 1)
    state.gas -= gas_cost

    if state.gas < 0
        return PvmExit(OUT_OF_GAS, 0)
    end

    # Get skip distance for this instruction
    skip = skip_distance(state.opcode_mask, state.pc)

    # Execute instruction based on opcode
    if opcode == 0x00  # trap
        return PvmExit(PANIC, 0)

    elseif opcode == 0x01  # fallthrough
        return PvmExit(HALT, 0)

    elseif opcode == 0x02  # load_imm
        if state.pc + 2 > length(state.instructions)
            return PvmExit(PANIC, 0)
        end

        reg = state.instructions[state.pc + 2] & 0x0f
        size = (state.instructions[state.pc + 2] >> 4) & 0x0f

        if reg >= 13
            return PvmExit(PANIC, 0)
        end

        value = load_immediate(state.instructions, state.pc + 2, Int(size))
        state.registers[reg + 1] = value

    elseif opcode == 0x03  # load_u8
        if state.pc + 2 > length(state.instructions)
            return PvmExit(PANIC, 0)
        end

        dst_reg = state.instructions[state.pc + 2] & 0x0f
        src_reg = (state.instructions[state.pc + 2] >> 4) & 0x0f

        if dst_reg >= 13 || src_reg >= 13
            return PvmExit(PANIC, 0)
        end

        address = state.registers[src_reg + 1]
        result = read_memory(state.memory, address, 1)

        if result isa Symbol
            if result == :panic
                return PvmExit(PANIC, 0)
            elseif result == :fault
                return PvmExit(FAULT, address)
            end
        else
            state.registers[dst_reg + 1] = UInt64(result[1])
        end

    elseif opcode == 0x07  # store_u8
        if state.pc + 2 > length(state.instructions)
            return PvmExit(PANIC, 0)
        end

        addr_reg = state.instructions[state.pc + 2] & 0x0f
        val_reg = (state.instructions[state.pc + 2] >> 4) & 0x0f

        if addr_reg >= 13 || val_reg >= 13
            return PvmExit(PANIC, 0)
        end

        address = state.registers[addr_reg + 1]
        value = UInt8(state.registers[val_reg + 1] & 0xff)

        result = write_memory!(state.memory, address, [value])

        if result isa Symbol
            if result == :panic
                return PvmExit(PANIC, 0)
            elseif result == :fault
                return PvmExit(FAULT, address)
            end
        end

    elseif opcode == 0x0b  # jump
        if state.pc + 4 > length(state.instructions)
            return PvmExit(PANIC, 0)
        end

        # Read 24-bit target address (little-endian)
        target = UInt32(state.instructions[state.pc + 2]) |
                (UInt32(state.instructions[state.pc + 3]) << 8) |
                (UInt32(state.instructions[state.pc + 4]) << 16)

        # Validate jump target is start of basic block
        if target >= length(state.opcode_mask) || !state.opcode_mask[target + 1]
            return PvmExit(PANIC, 0)
        end

        state.pc = target
        return PvmExit(HALT, 0)  # Continue execution (not actually halt)

    else
        # Unknown instruction
        return PvmExit(PANIC, 0)
    end

    # Advance PC by instruction length
    state.pc += 1 + skip

    return PvmExit(HALT, 0)  # Continue execution
end

# Main PVM execution function
function execute_pvm(
    program_blob::Vector{UInt8},
    initial_pc::UInt32,
    initial_gas::Int64,
    initial_registers::Vector{PvmReg},
    initial_memory::PvmMemory
)::Tuple{PvmExit, UInt32, Int64, Vector{PvmReg}, PvmMemory}

    # Decode program
    try
        instructions, opcode_mask, jump_table = decode_program_blob(program_blob)

        # Create initial state
        state = PvmState()
        state.instructions = instructions
        state.opcode_mask = opcode_mask
        state.jump_table = jump_table
        state.pc = initial_pc
        state.gas = initial_gas
        state.registers = copy(initial_registers)
        state.memory = initial_memory

        # Execute until halt/panic/oog/fault
        max_steps = 1000000  # Prevent infinite loops
        steps = 0

        while steps < max_steps
            steps += 1

            exit_result = execute_instruction(state)

            if exit_result.reason == HALT && exit_result.data == 0
                # Continue execution (this was not a real halt)
                continue
            else
                # Actual exit condition
                return (exit_result, state.pc, state.gas, state.registers, state.memory)
            end
        end

        # Exceeded max steps
        return (PvmExit(PANIC, 0), state.pc, state.gas, state.registers, state.memory)

    catch e
        # Program decode failed
        empty_memory = PvmMemory()
        return (PvmExit(PANIC, 0), initial_pc, initial_gas, initial_registers, empty_memory)
    end
end

# High-level PVM invocation
function invoke_pvm(
    program_blob::Vector{UInt8},
    gas_limit::Gas,
    initial_memory_pages::Vector{Tuple{UInt32, Vector{UInt8}}} = Vector{Tuple{UInt32, Vector{UInt8}}}()
)::Tuple{Bool, Vector{UInt8}, Gas, Dict{String, Any}}

    # Setup initial state
    initial_registers = zeros(PvmReg, 13)
    initial_memory = PvmMemory()

    # Load initial memory pages
    for (page_num, data) in initial_memory_pages
        initial_memory.pages[page_num] = copy(data)
        push!(initial_memory.readable_pages, page_num)
        push!(initial_memory.writable_pages, page_num)
    end

    # Execute
    (exit_result, final_pc, remaining_gas, final_registers, final_memory) = execute_pvm(
        program_blob,
        UInt32(0),  # start at PC 0
        Int64(gas_limit),
        initial_registers,
        initial_memory
    )

    # Process results
    success = exit_result.reason == HALT
    output = Vector{UInt8}()
    gas_used = Gas(max(0, Int64(gas_limit) - remaining_gas))

    # Extract output from memory (convention: output at address 0x10000)
    if success
        output_result = read_memory(final_memory, 0x10000, 1024)
        if output_result isa Vector{UInt8}
            output = output_result
        end
    end

    # Collect exports
    exports = Dict{String, Any}()
    exports["final_pc"] = final_pc
    exports["final_registers"] = final_registers
    exports["exit_reason"] = exit_result.reason
    exports["exit_data"] = exit_result.data

    return (success, output, gas_used, exports)
end

# Create memory page
function create_memory_page(data::Vector{UInt8})::Vector{UInt8}
    page = zeros(UInt8, PVM_PAGE_SIZE)
    copy_len = min(length(data), PVM_PAGE_SIZE)
    page[1:copy_len] = data[1:copy_len]
    return page
end

export PvmState, PvmMemory, PvmExit, PvmExitReason,
       HALT, PANIC, OUT_OF_GAS, FAULT, HOST_CALL,
       execute_pvm, invoke_pvm, create_memory_page,
       decode_program_blob