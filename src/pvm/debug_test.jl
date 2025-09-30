include("pvm.jl")
using .PVM

# Test simple program
instructions = UInt8[0x01]  # Just a fallthrough
opcode_mask = BitVector([1])

# Create blob manually
blob = UInt8[]
push!(blob, 0)  # jump count
push!(blob, 1)  # jump size
push!(blob, length(instructions))  # code length

# Add instructions
append!(blob, instructions)

# Add opcode mask
for bit in opcode_mask
    push!(blob, UInt8(bit))
end

println("Blob: $blob")
println("Blob length: $(length(blob))")

result = PVM.deblob(blob)
if result !== nothing
    inst, mask, jumps = result
    println("Success!")
    println("Instructions: $inst")
    println("Mask: $mask")
    println("Jumps: $jumps")

    # Try to execute
    state = PVM.PVMState(
        0, Int64(100), zeros(UInt64, 13),
        PVM.Memory(), :continue,
        inst, mask, jumps
    )

    println("\nBefore step: PC=$(state.pc), status=$(state.status)")
    PVM.step!(state)
    println("After step: PC=$(state.pc), status=$(state.status)")
else
    println("Failed to decode!")
end