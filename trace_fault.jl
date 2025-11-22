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

                    # Check instruction at 0x1c6d (step 13 fault)
                    pc = 0x1c6d
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

                    println("PC=0x$(string(pc, base=16)): store_ind_u32 [r$rb + $immx_signed] = r$ra")
                    println()

                    # r1 at step 13 was 0xFEFD0200 (4278059776)
                    # Let's trace what rb is and what value it holds
                    println("If rb=$rb is r$(rb), need to know its value at step 13")

                    # r1 (rb=1) = 0xFEFD0200
                    if rb == 1
                        addr = UInt64(0xFEFD0200) + immx_signed
                        println("addr = 0x$(string(addr, base=16))")
                        page = div(addr, 4096)
                        println("Page = $page (0x$(string(page, base=16)))")
                        println()
                        println("This page needs to be WRITE accessible")
                    end
                end
                break
            end
        end
        break
    end
end
