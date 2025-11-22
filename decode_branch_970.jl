#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/enqueue_and_unlock_chain-3.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    # Decode branch at PC=0x32d5 (step 970)
                    pc = 0x32d5
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    # For branch_ne (opcode 171), format is: opcode, regs, offset
                    # The branch compares ra and rb, jumps if not equal
                    lx = min(4, max(0, skip - 1))
                    offset_val = UInt64(0)
                    for i in 0:lx-1
                        byte = instructions[pc + 2 + i + 1]
                        offset_val |= UInt64(byte) << (8*i)
                    end
                    if lx > 0 && (offset_val >> (8*lx - 1)) & 1 == 1
                        offset_val |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    offset = reinterpret(Int32, offset_val % UInt32)

                    println("Step 970: PC=0x32d5 branch_ne")
                    println("  opcode=$opcode (branch_ne)")
                    println("  skip=$skip")
                    println("  ra=$ra (r$ra), rb=$rb (r$rb)")
                    println("  offset=$offset")
                    println("  Bytes: [$(join(["0x" * string(instructions[pc+i+1], base=16, pad=2) for i in 0:skip], " "))]")

                    # Branch logic: if r_ra != r_rb, jump to PC + offset
                    # Otherwise fall through to PC + 1 + skip
                    println("\n  Branch logic: if r$ra != r$rb, jump to PC + $offset = 0x$(string(pc + offset, base=16))")
                    println("                else fall through to 0x$(string(pc + 1 + skip, base=16))")

                    # From trace: r8 = 0x114c2, r10 = 1
                    println("\n  At step 970:")
                    println("    r8 = 0x114c2 = 70850")
                    println("    r10 = 1")
                    println("    Since r$ra ($(ra == 8 ? "r8" : "r$ra")) != r$rb ($(rb == 10 ? "r10" : "r$rb")), branch is taken")
                end
                break
            end
        end
        break
    end
end
