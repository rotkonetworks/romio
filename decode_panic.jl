#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

# Get service 1729 code
acc = nothing
for a in data[:pre_state][:accounts]
    if a[:id] == 1729
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

# Decode instruction at PC=0x32a0 (panic location)
pc = 0x32a0
opcode = instructions[pc + 1]
skip = PVM.skip_distance(opcode_mask, pc + 1)

println("Instruction at PC=0x$(string(pc, base=16)):")
println("  opcode: $opcode")
println("  skip: $skip")

# For load_imm_jump_ind (opcode 180):
# Format: r_a = imm, jump [r_b]
if opcode == 180
    reg_byte = instructions[pc + 2]
    ra = reg_byte & 0x0F
    rb = (reg_byte >> 4) & 0x0F

    # Decode immediate
    lx = min(4, max(0, skip - 1))
    imm = Int64(0)
    for j in 0:lx-1
        byte = instructions[pc + 2 + j + 1]
        global imm |= Int64(byte) << (8*j)
    end
    if lx > 0 && (imm >> (8*lx - 1)) & 1 == 1
        imm |= ~((Int64(1) << (8*lx)) - 1)
    end

    println("  load_imm_jump_ind: r$ra = $imm, jump [r$rb]")
    println()
    println("At panic, register values suggest:")
    if rb <= 12
        println("  The jump target is in r$rb")
        println("  If r$rb contains an invalid address, the jump fails")
    end
end

# Also check bytes around the instruction
println("\nRaw bytes at PC=0x$(string(pc, base=16)):")
for i in 0:min(5, length(instructions) - pc - 1)
    println("  byte $i: 0x$(string(instructions[pc + 1 + i], base=16, pad=2))")
end
