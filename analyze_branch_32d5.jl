#!/usr/bin/env julia
# Analyze branch at PC=0x32d5

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

                    pc = 0x32d5
                    skip = PVM.skip_distance(opcode_mask, pc + 1)

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    lx = min(4, max(0, skip - 1))

                    # Decode offset
                    offset_val = UInt64(0)
                    for i in 0:lx-1
                        byte = instructions[pc + 2 + i + 1]
                        offset_val |= UInt64(byte) << (8*i)
                    end
                    if lx > 0 && (offset_val >> (8*lx - 1)) & 1 == 1
                        offset_val |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    offset = reinterpret(Int32, offset_val % UInt32)

                    println("PC=0x32d5: branch_ne r$ra, r$rb, $offset")
                    println("  Bytes: [$(join(["0x$(string(instructions[pc+i+1], base=16, pad=2))" for i in 0:skip], " "))]")
                    println("  If r$ra != r$rb, jump to PC + $offset = 0x$(string(pc + offset, base=16))")
                    println("  Else fall through to PC + $(1+skip) = 0x$(string(pc + 1 + skip, base=16))")
                end
                break
            end
        end
        break
    end
end
