# Simple PVM test - just halt immediately

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

println("=== Simple PVM Test ===\n")

# Test: Immediate halt via jump_ind
# Register 0 (RA) is initialized to 0xFFFF0000 (halt address)
# jump_ind with register 0 and immediate 0 should jump to halt address
println("Test: Immediate halt via jump_ind")
instructions = UInt8[
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00  # jump_ind r0, 0 -> jumps to value in r0
]
mask = BitVector([1, 0, 0, 0, 0, 0])
# Need a jump table with the halt address since jump_ind uses dynamic addressing
# Actually, jump_ind calculates (r0 + immediate) and looks it up in jump table
# For halt, we need addr = 0xFFFF0000 directly

# Let's try different approach: use a jump table entry
# The halt address is 0xFFFF0000 = 2^32 - 2^16
# But we can't use jump_ind to halt directly, we need the special halt address

# According to spec, jump_ind with address 0xFFFF0000 triggers halt
# Register 0 starts at 0xFFFF0000
# jump_ind r0, 0 means: addr = (r0 + 0) = 0xFFFF0000, which should halt!

blob = create_blob(instructions, mask)

status, output, gas = PVM.execute(blob, UInt8[], UInt64(100))
println("  Status: $status (expected: halt)")
println("  Gas used: $gas")
println("  Output length: $(length(output))")

if status == :halt
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
end

println("\n=== Test Complete ===")
