#!/usr/bin/env julia
# Analyze instruction at PC=0x329a (step 977)

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

                    println("=== STEP 977: PC=0x329a, opcode=0x82 (load_ind_u64) ===\n")

                    pc = 0x329a
                    opcode = instructions[pc + 1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode)")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    # Show instruction bytes
                    println("\nInstruction bytes:")
                    for i in 0:min(skip + 3, 10)
                        byte = instructions[pc + i + 1]
                        println("  [PC+$i] = 0x$(string(byte, base=16, pad=2))")
                    end

                    # Decode
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("\nRegister byte [PC+1]: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra, rb=$rb")

                    lx = min(4, max(0, skip - 1))
                    println("\nlx: $lx")

                    # Decode immediate
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        byte = instructions[byte_pos + 1]
                        immx |= UInt64(byte) << (8*i)
                    end
                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    println("Immediate: $immx = 0x$(string(immx, base=16))")

                    println("\nInstruction: r$ra ← load_u64(r$rb + $immx)")
                end
                break
            end
        end
        break
    end
end
