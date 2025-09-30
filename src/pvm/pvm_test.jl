# Test the PVM interpreter
include("pvm.jl")
using .PVM

# Create a simple test program
# This program:
# 1. Loads immediate value 42 into register 0
# 2. Loads immediate value 58 into register 1
# 3. Adds them (result in register 2)
# 4. Halts

function create_test_program()
    # Instruction bytes
    instructions = UInt8[
        0x33,  # load_imm (opcode 51)
        0x00,  # register 0
        42,    # immediate value 42

        0x33,  # load_imm
        0x10,  # register 1
        58,    # immediate value 58

        0xBE,  # add_32 (opcode 190)
        0x10,  # ra=0, rb=1
        0x20,  # rd=2

        0x32,  # jump_ind (opcode 50)
        0x00,  # register 0
        0xFF, 0xFF, 0xFF, 0xFF  # offset to trigger halt
    ]

    # Create opcode mask (1 where opcode, 0 for arguments)
    opcode_mask = BitVector([
        1, 0, 0,  # load_imm
        1, 0, 0,  # load_imm
        1, 0, 0,  # add_32
        1, 0, 0, 0, 0, 0  # jump_ind
    ])

    # Empty jump table
    jump_table = UInt32[]

    # Encode as blob
    # Format: jump_count, jump_size, code_len, jump_table, instructions, opcode_mask
    blob = UInt8[]

    # Jump count (0)
    push!(blob, 0)

    # Jump size (1 byte)
    push!(blob, 1)

    # Code length
    push!(blob, length(instructions))

    # No jump table entries

    # Instructions
    append!(blob, instructions)

    # Opcode mask
    for bit in opcode_mask
        push!(blob, UInt8(bit))
    end

    return blob
end

# Test basic execution
function test_basic_execution()
    println("Testing basic PVM execution...")

    program = create_test_program()
    input = UInt8[]
    gas = UInt64(1000)

    try
        status, output, gas_used = PVM.execute(program, input, gas)
        println("Execution status: $status")
        println("Gas used: $gas_used")
        println("Output: $output")
    catch e
        println("Error during execution: $e")
        println(stacktrace(catch_backtrace()))
    end
end

# Test memory access
function test_memory_access()
    println("\nTesting memory access...")

    # Create a state manually for testing
    state = PVM.PVMState(
        UInt32(0),  # pc
        Int64(1000),  # gas
        zeros(UInt64, 13),  # registers
        PVM.Memory(),  # memory
        :continue,  # status
        UInt8[0x01],  # dummy instruction
        BitVector([1]),  # opcode mask
        UInt32[]  # jump table
    )

    # Test writing and reading
    addr = UInt64(0x100000)  # Above the forbidden zone

    # Mark page as writable
    page = div(UInt32(addr), PVM.PAGE_SIZE)
    state.memory.access[page + 1] = PVM.WRITE

    # Write a value
    PVM.write_u8(state, addr, 0x42)

    # Mark as readable
    state.memory.access[page + 1] = PVM.READ

    # Read it back
    val = PVM.read_u8(state, addr)
    println("Write/Read test: wrote 0x42, read 0x$(string(val, base=16))")

    # Test forbidden zone access
    forbidden_addr = UInt64(0x1000)  # In forbidden zone
    PVM.read_u8(state, forbidden_addr)
    println("Forbidden zone access status: $(state.status)")
end

# Run tests
println("=== PVM Interpreter Tests ===")
test_basic_execution()
test_memory_access()
println("\n=== Tests Complete ===")