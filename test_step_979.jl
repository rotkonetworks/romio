#!/usr/bin/env julia
# Analyze step 979 - opcode 0xb4 (load_imm_jump_ind)

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

                    println("=== STEP 979: PC=0x32a0, opcode=0xb4 (load_imm_jump_ind) ===\n")

                    pc = 0x32a0
                    opcode = instructions[pc + 1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode)")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    # Show instruction bytes
                    println("\nInstruction bytes:")
                    for i in 0:min(skip, 10)
                        byte = instructions[pc + i + 1]
                        println("  [PC+$i] = 0x$(string(byte, base=16, pad=2))")
                    end

                    # Decode according to our implementation
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("\nRegister byte [PC+1]: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra, rb=$rb")

                    # Length byte
                    len_byte = instructions[pc + 3]
                    lx = Int(min(4, len_byte % 8))
                    ly = min(4, max(0, skip - lx - 2))
                    println("\nLength byte [PC+2]: 0x$(string(len_byte, base=16, pad=2))")
                    println("  lx (immx length): $lx")
                    println("  ly (immy length): $ly")
                    println("  skip - lx - 2 = $skip - $lx - 2 = $(skip - lx - 2)")

                    # Decode immediates manually
                    println("\nImmediate X (starts at PC+3):")
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 3 + i
                        byte = instructions[byte_pos + 1]
                        immx |= UInt64(byte) << (8*i)
                        println("  [PC+$(3+i)] = 0x$(string(byte, base=16, pad=2))")
                    end
                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    println("  Decoded immx: $immx = 0x$(string(immx, base=16))")

                    println("\nImmediate Y (starts at PC+$(3+lx)):")
                    immy = UInt64(0)
                    for i in 0:ly-1
                        byte_pos = pc + 3 + lx + i
                        if byte_pos + 1 <= length(instructions)
                            byte = instructions[byte_pos + 1]
                            immy |= UInt64(byte) << (8*i)
                            println("  [PC+$(3+lx+i)] = 0x$(string(byte, base=16, pad=2))")
                        end
                    end
                    # Sign extend
                    if ly > 0 && (immy >> (8*ly - 1)) & 1 == 1
                        immy |= ~((UInt64(1) << (8*ly)) - 1)
                    end
                    println("  Decoded immy: $immy = 0x$(string(immy, base=16))")

                    # From trace: r8=3978425819141910832 at step 978
                    r8_value = 3978425819141910832
                    println("\nExecution (from trace: r8=0x$(string(r8_value, base=16))):")
                    println("  1. Load r$ra ← immx = $immx")
                    println("  2. addr ← r$rb + immy = $r8_value + $immy = $(r8_value + immy)")

                    addr = (r8_value + immy) % 2^32
                    println("     addr (mod 2^32) = $addr = 0x$(string(addr, base=16))")

                    if addr == 2^32 - 2^16
                        println("  3. addr == HALT_ADDRESS → HALT")
                    elseif addr == 0 || addr % PVM.DYNAM_ALIGN != 0
                        println("  3. addr not aligned → PANIC")
                    else
                        idx = div(addr, PVM.DYNAM_ALIGN) - 1
                        println("  3. idx = addr / $(PVM.DYNAM_ALIGN) - 1 = $idx")
                        if idx >= length(jump_table)
                            println("     idx >= jump_table_length → PANIC")
                        else
                            target = jump_table[idx + 1]
                            println("     PC ← jump_table[$idx] = 0x$(string(target, base=16))")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
