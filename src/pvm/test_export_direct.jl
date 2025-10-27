# test_export_direct.jl
# Direct test of export host call function

include("pvm.jl")
using .PVM
using .PVM.HostCalls

println("=== Direct EXPORT Host Call Test ===\n")

# Create a mock state
mutable struct MockState
    gas::Int64
    registers::Vector{UInt64}
    memory::PVM.Memory
    status::Symbol
    exports::Vector{Vector{UInt8}}
end

# Create memory and mark some pages as writable
mem = PVM.Memory()
# 0x20000 = 131072, 131072 / 4096 = 32 (page index 0-based)
# In Julia (1-indexed), that's page 33
# Mark pages 33-35 as writable
for i in 33:35
    mem.access[i] = :write
end

# Create state
state = MockState(
    1000,  # gas
    zeros(UInt64, 13),  # registers
    mem,
    :host,
    Vector{UInt8}[]  # exports
)

# Write some test data to memory at 0x20000
test_data = UInt8[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
for (i, byte) in enumerate(test_data)
    state.memory.data[0x20000 + i] = byte
end

# Setup registers for export call
# r7 (registers[8]): memory address to export from
# r8 (registers[9]): length of data
# r9 (registers[10]): address to write gas consumed
state.registers[8] = UInt64(0x20000)  # r7: export from 0x20000
state.registers[9] = UInt64(16)        # r8: export 16 bytes
state.registers[10] = UInt64(0x21000) # r9: write gas to 0x21000

println("Before export:")
println("  Gas: $(state.gas)")
println("  Exports: $(length(state.exports))")
println("  r7 (mem addr): 0x$(string(state.registers[8], base=16))")
println("  r8 (length): $(state.registers[9])")
println("  r9 (gas addr): 0x$(string(state.registers[10], base=16))")

# Call export
context = HostCalls.HostCallContext(nothing, UInt32(0), nothing)
state = HostCalls.host_call_export(state, context)

println("\nAfter export:")
println("  Gas: $(state.gas)")
println("  Status: $(state.status)")
println("  Exports: $(length(state.exports))")
println("  r7 (result): $(state.registers[8])")

if length(state.exports) == 1
    println("  Export[1] length: $(length(state.exports[1]))")
    println("  Export[1] data: $(state.exports[1])")

    # Check if data matches
    if state.exports[1] == test_data
        println("  ✓ TEST PASSED - Export data matches!")
    else
        println("  ✗ TEST FAILED - Data mismatch")
    end
else
    println("  ✗ TEST FAILED - Wrong number of exports")
end

# Check gas consumed value written to memory
gas_bytes = state.memory.data[0x21001:0x21008]
gas_consumed_val = UInt64(0)
for (i, byte) in enumerate(gas_bytes)
    gas_consumed_val += UInt64(byte) << (8 * (i-1))
end
println("  Gas consumed value written: $gas_consumed_val")

println("\nDirect test complete!")
