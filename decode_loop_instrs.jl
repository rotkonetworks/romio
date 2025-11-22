#!/usr/bin/env julia
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

                    for pc in [0x32b5, 0x32b8, 0x32d2, 0x3327, 0x492c, 0x492f]
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        reg_byte = instructions[pc + 2]
                        ra = reg_byte & 0x0F
                        rb = reg_byte >> 4

                        println("PC=0x", string(pc, base=16), ": opcode=", opcode, " skip=", skip)
                        bytes_str = join(["0x" * string(instructions[pc+i+1], base=16, pad=2) for i in 0:skip], " ")
                        println("  Bytes: [", bytes_str, "]")
                        println("  reg_byte=0x", string(reg_byte, base=16), " -> ra=", ra, " (r", ra, "), rb=", rb, " (r", rb, ")")

                        if opcode == 130  # load_ind_u64
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
                            println("  -> r", ra, " = load_u64(r", rb, " + ", immx_signed, ")")
                        elseif opcode == 149  # add_imm_64
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
                            println("  -> r", ra, " = r", rb, " + ", immx_signed)
                        end
                        println()
                    end
                end
                break
            end
        end
        break
    end
end
