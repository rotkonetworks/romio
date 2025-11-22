#!/usr/bin/env julia
# Check branch instruction details

using JSON3
include("src/pvm/pvm.jl")

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob_bytes)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    println("=== BRANCH AT 0x4792 ANALYSIS ===\n")

                    pc = 0x4792
                    opcode = instructions[pc+1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2))")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    reg_byte = instructions[pc+2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("Register byte: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra, rb=$rb")

                    # Decode offset (signed)
                    lx = min(4, max(0, skip - 1))
                    println("Offset length (lx): $lx")

                    # Read immediate bytes
                    offset_val = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        if byte_pos + 1 <= length(instructions)
                            byte = instructions[byte_pos+1]
                            offset_val |= UInt64(byte) << (8*i)
                            println("  Offset byte $i at 0x$(string(byte_pos, base=16)): 0x$(string(byte, base=16, pad=2))")
                        end
                    end

                    # Sign extend
                    if lx > 0 && (offset_val >> (8*lx - 1)) & 1 == 1
                        offset_val |= ~((UInt64(1) << (8*lx)) - 1)
                    end

                    println("Raw offset value: 0x$(string(offset_val, base=16, pad=16))")
                    println("As signed 32-bit: $(Int32(offset_val & 0xFFFFFFFF))")

                    # What would the target PC be?
                    next_pc = pc + 1 + skip
                    branch_target = next_pc + Int32(offset_val & 0xFFFFFFFF)
                    println("\nIf branch NOT taken: PC = 0x$(string(next_pc, base=16))")
                    println("If branch TAKEN: PC = 0x$(string(branch_target, base=16))")

                    # Check what instruction is at the fall-through
                    println("\nInstruction at fall-through (0x$(string(next_pc, base=16))):")
                    if next_pc + 1 <= length(instructions)
                        fallthrough_opcode = instructions[next_pc+1]
                        println("  Opcode: 0x$(string(fallthrough_opcode, base=16, pad=2))")
                    end

                    # Check what instruction is at the branch target
                    println("\nInstruction at branch target (0x$(string(branch_target, base=16))):")
                    if branch_target + 1 <= length(instructions) && branch_target >= 0
                        target_opcode = instructions[branch_target+1]
                        println("  Opcode: 0x$(string(target_opcode, base=16, pad=2))")
                    end
                end
                break
            end
        end
        break
    end
end
