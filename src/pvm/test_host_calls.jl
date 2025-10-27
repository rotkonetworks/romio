# Test host call integration

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

println("=== PVM Host Call Tests ===\n")

# Test 1: Gas host call
println("Test 1: Gas host call (ID=0)")
println("  This test invokes the gas host call and verifies it returns remaining gas")

# Program:
# 1. Call host call 0 (gas) - should put remaining gas in r7
# 2. Halt via jump to halt address
instructions = UInt8[
    0x0A, 0x00,                           # ecalli 0 - host call ID 0 (gas)
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00   # jump_ind r0, 0 -> jumps to halt address
]
mask = BitVector([1, 0, 1, 0, 0, 0, 0, 0])

blob = create_blob(instructions, mask)
initial_gas = 1000
status, output, gas_used = PVM.execute(blob, UInt8[], UInt64(initial_gas))

println("  Status: $status (expected: halt)")
println("  Gas used: $gas_used")
println("  Remaining gas should be: $(initial_gas - gas_used)")

# Gas costs:
# - ecalli instruction: 1 gas
# - gas host call: 10 gas
# - jump_ind instruction: 1 gas
# Total gas used: 12

expected_gas_used = 12
if status == :halt && gas_used == expected_gas_used
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
    println("    Expected gas used: $expected_gas_used, got: $gas_used")
end

println("\n" * "="^50)

# Test 2: Unknown host call
println("\nTest 2: Unknown host call (ID=99)")
println("  This test invokes an unknown host call and expects WHAT error")

instructions = UInt8[
    0x0A, 0x63,                           # ecalli 99 - unknown host call
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00   # jump_ind r0, 0 -> halt
]
mask = BitVector([1, 0, 1, 0, 0, 0, 0, 0])

blob = create_blob(instructions, mask)
status, output, gas_used = PVM.execute(blob, UInt8[], UInt64(1000))

println("  Status: $status (expected: halt)")
println("  Gas used: $gas_used")

# ecalli costs 1, unknown host call costs 10, jump costs 1
expected_gas_used = 12
if status == :halt && gas_used == expected_gas_used
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
    println("    Expected gas used: $expected_gas_used, got: $gas_used")
end

println("\n" * "="^50)

# Test 3: Host call with insufficient gas
println("\nTest 3: Host call with insufficient gas")
println("  This test invokes a host call with only 5 gas (needs 10)")

instructions = UInt8[
    0x0A, 0x00,                           # ecalli 0 - gas host call (costs 10)
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00   # jump_ind r0, 0 -> halt
]
mask = BitVector([1, 0, 1, 0, 0, 0, 0, 0])

blob = create_blob(instructions, mask)
status, output, gas_used = PVM.execute(blob, UInt8[], UInt64(5))

println("  Status: $status (expected: oog - out of gas)")

if status == :oog
    println("  ✓ TEST PASSED")
else
    println("  ✗ TEST FAILED")
    println("    Expected status :oog, got: $status")
end

println("\n=== All Tests Complete ===")
