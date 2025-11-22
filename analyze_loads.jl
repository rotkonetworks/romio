#!/usr/bin/env julia
# Analyze the consecutive load instructions at steps 975-978

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

                    println("=== Analyzing load_ind_u64 instructions at PC=0x3294-0x329d ===\n")

                    for pc in [0x3294, 0x3297, 0x329a, 0x329d]
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        reg_byte = instructions[pc + 2]
                        ra = reg_byte & 0x0F
                        rb = reg_byte >> 4

                        lx = min(4, max(0, skip - 1))

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

                        immx_signed = reinterpret(Int64, immx)

                        println("PC=0x$(string(pc, base=16)): r$ra ← load_u64(r$rb + $immx_signed)")
                        println("  bytes: [0x$(join([string(instructions[pc + i + 1], base=16, pad=2) for i in 0:skip], " 0x"))]")
                        println()
                    end
                end
                break
            end
        end
        break
    end
end
