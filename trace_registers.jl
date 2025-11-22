#!/usr/bin/env julia
# Trace actual PVM execution to see register values at branch points
include("src/pvm/pvm.jl")
include("src/stf/accumulate.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

# Get service 1729 code
service_id = 1729
acc = nothing
for a in data[:pre_state][:accounts]
    if a[:id] == service_id
        global acc = a
        break
    end
end

code_blob = nothing
for preimage in acc[:data][:preimages_blob]
    if length(preimage[:blob]) > 10000
        blob_hex = preimage[:blob]
        hex_str = blob_hex[3:end]
        global code_blob = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]
        break
    end
end

result = PVM.deblob(code_blob)
instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

# Build input
timeslot = UInt32(data[:input][:slot])
count = UInt32(length(data[:input][:reports][1][:results]))

input = UInt8[]
append!(input, reinterpret(UInt8, [timeslot]))
append!(input, reinterpret(UInt8, [service_id]))
append!(input, reinterpret(UInt8, [count]))

# Initialize PVM state manually to trace
PAGE_SIZE = UInt32(4096)
ZONE_SIZE = UInt32(65536)
MAX_INPUT = UInt32(2^14)

registers = zeros(UInt64, 13)
registers[1] = UInt64(timeslot)  # r0
registers[2] = UInt64(2^32 - 2*ZONE_SIZE - MAX_INPUT)  # r1/SP
registers[8] = UInt64(2^32 - ZONE_SIZE - MAX_INPUT)  # r7 = input_addr
registers[9] = UInt64(2^32 - ZONE_SIZE - MAX_INPUT)  # r8 = input_addr

sp = registers[2]
println("Initial state:")
println("  SP (r1) = 0x$(string(sp, base=16))")
println("  r5 = $(registers[6])")
println("  r6 = $(registers[7])")
println("  r7 = 0x$(string(registers[8], base=16))")
println("  r8 = 0x$(string(registers[9], base=16))")

# Simulate the first few instructions
println("\nSimulating entry prologue:")

# 1. r9 = [SP+48]
# Currently SP+48 = 0 (uninitialized)
sp48_value = UInt64(0)  # Uninitialized stack
println("  [SP+48] = $sp48_value")
r9 = sp48_value

# 2. r9 = r9 - r5
r5 = registers[6]
r9 = r9 - r5
println("  r9 = [SP+48] - r5 = $sp48_value - $r5 = $r9")

# 3. r7 = [SP+40]
sp40_value = UInt64(0)  # Uninitialized
println("  [SP+40] = $sp40_value")
r7 = sp40_value

# 4. r7 = r7 - r5
r7 = r7 - r5
println("  r7 = [SP+40] - r5 = $sp40_value - $r5 = $r7")

# 5. r5 = r5 + r6
r6 = registers[7]
r5_new = r5 + r6
println("  r5 = r5 + r6 = $r5 + $r6 = $r5_new")

# 6. r8 = [SP+56]
sp56_value = UInt64(0)
println("  r8 = [SP+56] = $sp56_value")

# 8. r10 = [SP+32]
sp32_value = UInt64(0)
println("  r10 = [SP+32] = $sp32_value")

println("\nBranch checks:")
println("  if r7 != 0 then error (r7=$r7) -> $(r7 != 0 ? "BRANCH TO ERROR" : "OK")")
println("  if r9 < 32 then error (r9=$r9) -> $(r9 < 32 ? "BRANCH TO ERROR" : "OK")")

# What values do we need?
println("\nRequired stack values for service 1729:")
println("  [SP+40] = r5 = $r5 (for r7=0)")
println("  [SP+48] >= r5 + 32 = $(r5 + 32) (for r9>=32)")
println("  [SP+32] = ? (used as r10)")
println("  [SP+56] = ? (used as r8)")
