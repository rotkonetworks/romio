#!/usr/bin/env julia
# Check instruction at PC 0x4795

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

                    println("=== INSTRUCTION AT PC 0x4795 ===\n")
                    pc = 0x4795

                    # Check if it's marked as opcode
                    is_opcode = opcode_mask[pc + 1]
                    println("Is opcode: $is_opcode")

                    if is_opcode
                        opcode = instructions[pc + 1]
                        println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode)")

                        skip = PVM.skip_distance(opcode_mask, pc + 1)
                        println("Skip: $skip")

                        if skip >= 1
                            reg_byte = instructions[pc + 2]
                            ra = reg_byte & 0x0F
                            rb = reg_byte >> 4
                            println("Register byte: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra, rb=$rb")
                        end

                        println("\nNext expected PC: 0x$(string(pc + 1 + skip, base=16))")
                    else
                        println("ERROR: PC 0x4795 is NOT marked as an opcode in the mask!")
                    end

                    # Show surrounding instructions
                    println("\n=== SURROUNDING INSTRUCTIONS ===")
                    for check_pc in 0x4790:0x47a0
                        if check_pc + 1 <= length(opcode_mask) && opcode_mask[check_pc + 1]
                            op = instructions[check_pc + 1]
                            sk = PVM.skip_distance(opcode_mask, check_pc + 1)
                            println("PC 0x$(string(check_pc, base=16)): opcode=0x$(string(op, base=16, pad=2)) skip=$sk")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
