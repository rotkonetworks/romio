#!/usr/bin/env julia
# Trace execution up to step 118 to see what causes the panic
include("src/pvm/pvm.jl")
include("src/stf/accumulate.jl")
using JSON3

# Load test case
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

entry_point = jump_table[11]  # Entry 10 = accumulate
println("Entry point: 0x$(string(entry_point, base=16))")

# Check if program still makes LOG call before panic
# Let's see what opcodes are between entry point and PC=0x32a0

# Trace opcodes at panic location (0x32a0)
pc = 0x32a0
println("\nAt panic location PC=0x$(string(pc, base=16)):")
if pc < length(instructions)
    opcode = instructions[pc + 1]
    skip = PVM.skip_distance(opcode_mask, pc + 1)
    println("  opcode: $opcode, skip: $skip")

    if opcode == 180  # load_imm_jump_ind
        reg_byte = instructions[pc + 2]
        ra = reg_byte & 0x0F
        rb = (reg_byte >> 4) & 0x0F
        println("  load_imm_jump_ind: r$ra = imm, jump [r$rb]")
        println("  This means r$rb contains a function pointer that is 0 (null)")
    end
end

# Also check what's around the first ecalli (FETCH at 0x0991)
println("\nFirst FETCH call location at PC=0x0991:")
pc = 0x0991
if pc < length(instructions)
    opcode = instructions[pc + 1]
    skip = PVM.skip_distance(opcode_mask, pc + 1)
    println("  opcode: $opcode, skip: $skip")
end

# Look at instructions around step 118
# With ~1-2 instructions per step on average, step 118 would be around PC ~100-200
# Let me check what's at different PCs

for check_pc in [0x3e0, 0x400, 0x420, 0x440]
    if check_pc < length(instructions)
        opcode = instructions[check_pc + 1]
        skip = PVM.skip_distance(opcode_mask, check_pc + 1)
        println("PC=0x$(string(check_pc, base=16)): opcode=$opcode skip=$skip")
    end
end
