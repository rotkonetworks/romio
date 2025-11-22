#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/work_for_ejected_service-3.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 1000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    # Check instruction at 0x1c80 (step 19 panic)
                    pc = 0x1c80
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    # Decode immediate
                    lx = min(4, max(0, skip - 1))
                    immx = UInt64(0)
                    for j in 0:lx-1
                        if pc + 2 + j < length(instructions)
                            byte = instructions[pc + 2 + j + 1]
                            immx |= UInt64(byte) << (8*j)
                        end
                    end
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    immx_signed = reinterpret(Int64, immx)

                    println("PC=0x$(string(pc, base=16)): jump_ind r$ra + $immx_signed")
                    println("jump_table has $(length(jump_table)) entries")

                    # At step 19, r0=0, r1=0xFEFD04A8
                    # Need to know what ra is to calculate address
                    if ra == 0
                        addr = UInt64(0) + immx
                        println("If r0=0, addr = $immx (0x$(string(addr, base=16)))")
                        idx = div(addr, 2) - 1
                        println("idx = $idx")
                        if idx >= length(jump_table)
                            println("PANIC: idx >= jump_table length ($(length(jump_table)))")
                        elseif addr == 0
                            println("PANIC: addr == 0")
                        elseif addr % 2 != 0
                            println("PANIC: addr not aligned")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
