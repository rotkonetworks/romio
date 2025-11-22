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

                    # Decode instruction at PC=0x3279 (step 248)
                    pc = 0x3279
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    lx = min(4, max(0, skip - 1))
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte = instructions[pc + 2 + i + 1]
                        immx |= UInt64(byte) << (8*i)
                    end
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    immx_signed = reinterpret(Int64, immx)

                    println("Step 248: PC=0x3279")
                    println("  opcode=$opcode ($(opcode == 123 ? "store_ind_u64" : "other"))")
                    println("  skip=$skip")
                    println("  ra=$ra (r$ra), rb=$rb (r$rb)")
                    println("  immediate=$immx_signed")
                    println("  Bytes: [$(join(["0x" * string(instructions[pc+i+1], base=16, pad=2) for i in 0:skip], " "))]")

                    # For store_ind_u64: mem[rb + immx] = ra
                    println("\n  Instruction: mem[r$rb + $immx_signed] = r$ra")
                    println("  This stores r$ra to address r$rb + $immx_signed")

                    # The value stored is 70850 which is r_ra
                    println("\n  Value stored: 70850 (0x114c2)")
                    println("  This value is at ro_data offset 0x14c2, which is likely a pointer to some data")
                end
                break
            end
        end
        break
    end
end
