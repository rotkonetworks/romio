#!/usr/bin/env julia
# Analyze the loop structure around step 960

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

                    println("=== Analyzing branch at PC=0x32b8 (step 960) ===\n")

                    pc = 0x32b8
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)

                    println("PC=0x$(string(pc, base=16)): opcode=0x$(string(opcode, base=16)) ($opcode) skip=$skip")

                    # Show bytes
                    println("Bytes: [$(join(["0x$(string(instructions[pc+i+1], base=16, pad=2))" for i in 0:skip], " "))]")

                    # Decode branch_ne_imm (opcode 82)
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4  # Should be unused for imm comparison

                    # For branch_ne_imm, format is: opcode, reg, length_byte, imm_value..., offset...
                    # Actually let me check the real format

                    println("\nRegister byte: 0x$(string(reg_byte, base=16)) → ra=$ra, rb=$rb")

                    # Need to decode the two immediates
                    len_byte = instructions[pc + 3]
                    println("Length byte: 0x$(string(len_byte, base=16))")

                    # Let me just show all the bytes for manual analysis
                    println("\nAll instruction bytes:")
                    for i in 0:skip
                        println("  [PC+$i] = 0x$(string(instructions[pc+i+1], base=16, pad=2))")
                    end
                end
                break
            end
        end
        break
    end
end
