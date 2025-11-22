#!/usr/bin/env julia
# Test opcode_mask fix

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

                    pc = 0x478d
                    println("\nOpcode mask AFTER MSB-FIRST FIX:")
                    for i in 0:6
                        idx = pc + i + 1
                        if idx <= length(opcode_mask)
                            is_opcode = opcode_mask[idx]
                            byte = instructions[idx]
                            println("  [0x$(string(pc+i, base=16))] mask=$(is_opcode ? 1 : 0) byte=0x$(string(byte, base=16, pad=2))")
                        end
                    end

                    pc_idx = pc + 1
                    skip = PVM.skip_distance(opcode_mask, pc_idx)
                    println("\nskip_distance from 0x478d: $skip")

                    # Calculate what lx would be
                    lx = min(4, max(0, skip - 1))
                    println("lx (immediate bytes): $lx")
                    println("\nExpected: skip=2, lx=1 (reads 1 byte = 0xff = 255)")
                end
                break
            end
        end
        break
    end
end
