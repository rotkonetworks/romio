# Test the PVM interpreter with various programs

include("pvm.jl")
using .PVM

function create_blob(instructions::Vector{UInt8}, opcode_mask::BitVector, jump_table::Vector{UInt32} = UInt32[])
    blob = UInt8[]

    # Encode header
    push!(blob, length(jump_table))  # jump count
    push!(blob, 4)  # jump size (4 bytes per entry)
    push!(blob, length(instructions))  # code length

    # Encode jump table
    for target in jump_table
        for i in 0:3
            push!(blob, UInt8((target >> (8*i)) & 0xFF))
        end
    end

    # Add instructions
    append!(blob, instructions)

    # Add opcode mask
    for bit in opcode_mask
        push!(blob, UInt8(bit))
    end

    return blob
end

println("=== PVM Interpreter Tests ===\n")

# Test 1: Simple fallthrough and halt
println("Test 1: Fallthrough and halt")
instructions1 = UInt8[
    0x01,  # fallthrough
    0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # jump_ind to halt address
]
mask1 = BitVector([1, 1, 0, 0, 0, 0, 0])
blob1 = create_blob(instructions1, mask1)

status1, output1, gas1 = PVM.execute(blob1, UInt8[], UInt64(100))
println("  Status: $status1 (expected: :halt)")
println("  Gas used: $gas1\n")

# Test 2: Load immediate and move
println("Test 2: Load immediate")
instructions2 = UInt8[
    0x14, 0x00, 42, 0, 0, 0, 0, 0,  # load_imm_64 r0, 42
    0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
]
mask2 = BitVector([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0])
blob2 = create_blob(instructions2, mask2)

# Need to examine the state to see register values
println("  Creating state to inspect...")
result = PVM.deblob(blob2)
if result !== nothing
    instructions, opcode_mask, jump_table = result
    println("  Decoded: $(length(instructions)) instructions, $(length(jump_table)) jumps")
    println("  Instructions: $([string(x, base=16, pad=2) for x in instructions])")
    println("  Opcode mask: $opcode_mask")

    state = PVM.PVMState(
        0, Int64(100), zeros(UInt64, 13),
        PVM.Memory(), :continue,
        instructions, opcode_mask, jump_table
    )

    # Set up initial registers
    state.registers[1] = 0xFFFF0000  # RA for halt

    # Execute the load instruction
    println("  Before step: PC=$(state.pc), status=$(state.status)")
    PVM.step!(state)
    println("  After load_imm_64: PC=$(state.pc), r0 = $(state.registers[1]), status=$(state.status)")

    # Execute halt
    PVM.step!(state)
    println("  Final: PC=$(state.pc), status=$(state.status)\n")
else
    println("  Failed to decode blob!\n")
end

# Test 3: Simple arithmetic
println("Test 3: Addition")
instructions3 = UInt8[
    0x33, 0x00, 30, 0, 0, 0,        # load_imm r0, 30
    0x33, 0x10, 12, 0, 0, 0,        # load_imm r1, 12
    0xBE, 0x10, 0x20,                # add_32 r2 = r0 + r1
    0x32, 0x20, 0xFF, 0xFF, 0xFF, 0xFF  # jump to halt using r2 (won't actually halt, just testing)
]
mask3 = BitVector([
    1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0,
    1, 0, 0,
    1, 0, 0, 0, 0, 0
])
blob3 = create_blob(instructions3, mask3)

result = PVM.deblob(blob3)
if result !== nothing
    instructions, opcode_mask, jump_table = result
    state = PVM.PVMState(
        0, Int64(100), zeros(UInt64, 13),
        PVM.Memory(), :continue,
        instructions, opcode_mask, jump_table
    )

    println("  Executing addition sequence...")

    # Execute load_imm r0, 30
    PVM.step!(state)
    println("  r0 = $(state.registers[1])")

    # Execute load_imm r1, 12
    PVM.step!(state)
    println("  r1 = $(state.registers[2])")

    # Execute add_32
    PVM.step!(state)
    println("  r2 = r0 + r1 = $(state.registers[3])")
    println("  Expected: 42\n")
end

# Test 4: Memory operations
println("Test 4: Memory load/store")
instructions4 = UInt8[
    0x33, 0x00, 99, 0, 0, 0,         # load_imm r0, 99
    0x3B, 0x00,                       # store_u8 [addr], r0
    0x00, 0x00, 0x10, 0x00,          # address = 0x100000
    0x34, 0x10,                       # load_u8 r1, [addr]
    0x00, 0x00, 0x10, 0x00,          # address = 0x100000
    0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
]
mask4 = BitVector([
    1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0
])
blob4 = create_blob(instructions4, mask4)

result = PVM.deblob(blob4)
if result !== nothing
    instructions, opcode_mask, jump_table = result
    state = PVM.PVMState(
        0, Int64(100), zeros(UInt64, 13),
        PVM.Memory(), :continue,
        instructions, opcode_mask, jump_table
    )

    # Set up memory page with write permission
    page_idx = div(0x100000, PVM.PAGE_SIZE)
    state.memory.access[page_idx + 1] = PVM.WRITE

    println("  Executing memory operations...")

    # Load immediate
    PVM.step!(state)
    println("  r0 = $(state.registers[1])")

    # Store to memory
    PVM.step!(state)

    # Set read permission for the load
    state.memory.access[page_idx + 1] = PVM.READ

    # Load from memory
    PVM.step!(state)
    println("  r1 = $(state.registers[2]) (loaded from memory)")
    println("  Memory test: $(state.registers[2] == 99 ? "✓ PASSED" : "✗ FAILED")\n")
end

# Test 5: Jump instruction
println("Test 5: Direct jump")
instructions5 = UInt8[
    0x28, 0x05, 0x00, 0x00, 0x00,   # jump +5
    0x00,                             # trap (should be skipped)
    0x00,                             # trap (should be skipped)
    0x00,                             # trap (should be skipped)
    0x00,                             # trap (should be skipped)
    0x01,                             # fallthrough (jump target)
    0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
]
mask5 = BitVector([1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
blob5 = create_blob(instructions5, mask5)

result = PVM.deblob(blob5)
if result !== nothing
    instructions, opcode_mask, jump_table = result
    state = PVM.PVMState(
        0, Int64(100), zeros(UInt64, 13),
        PVM.Memory(), :continue,
        instructions, opcode_mask, jump_table
    )

    state.registers[1] = 0xFFFF0000  # Set up halt address

    println("  PC before jump: $(state.pc)")
    PVM.step!(state)  # Execute jump
    println("  PC after jump: $(state.pc)")
    println("  Jump test: $(state.pc == 9 ? "✓ PASSED" : "✗ FAILED (expected 9)")")

    PVM.step!(state)  # Execute fallthrough
    println("  Status after fallthrough: $(state.status)")
end

println("\n=== Test Summary ===")
println("Basic instruction execution is working")
println("Issues to fix:")
println("- Halt mechanism needs proper setup")
println("- Memory permissions need better handling")
println("- Jump targets need validation")