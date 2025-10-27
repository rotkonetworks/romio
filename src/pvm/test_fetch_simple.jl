# Simple fetch test
include("pvm.jl")
using .PVM
using .PVM.HostCalls

println("Testing fetch host call...")

# Simple program that just halts
instructions = UInt8[
    0x32, 0x00, 0x00, 0x00, 0x00, 0x00   # jump_ind r0, 0 (halt)
]
mask = BitVector([1, 0, 0, 0, 0, 0])

code_len = length(instructions)
jump_count = 0
jump_size = 0

blob = UInt8[jump_count, jump_size, code_len]
append!(blob, instructions)

mask_bytes = UInt8[]
for b in mask
    push!(mask_bytes, b ? 0x01 : 0x00)
end
append!(blob, mask_bytes)

println("Created test blob")

# Test without context first
println("Test 1: Execute without context")
status, output, gas = PVM.execute(blob, UInt8[], UInt64(100))
println("  Status: $status, Gas used: $gas")

if status == :halt
    println("  ✓ Basic execution works")
else
    println("  ✗ Failed: $status")
    exit(1)
end

# Test with context
println("\nTest 2: Execute with context")
context = HostCalls.HostCallContext(nothing, UInt32(0), nothing)
status2, output2, gas2 = PVM.execute(blob, UInt8[], UInt64(100), context)
println("  Status: $status2, Gas used: $gas2")

if status2 == :halt
    println("  ✓ Execution with context works")
else
    println("  ✗ Failed: $status2")
    exit(1)
end

println("\n✅ All simple tests passed!")
