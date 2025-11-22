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

                    # Check first 4 instructions at entry point 10 (0x46e)
                    # These are load_ind_u64 from stack
                    start_pc = jump_table[11]
                    pc = start_pc

                    println("First 4 instructions at entry point 10:")
                    for i in 1:4
                        if pc >= length(instructions)
                            break
                        end

                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        if opcode == 130  # load_ind_u64
                            reg_byte = instructions[pc + 2]
                            ra = reg_byte & 0x0F
                            rb = reg_byte >> 4

                            # Decode immediate
                            lx = min(4, max(0, skip - 1))
                            immx = UInt64(0)
                            for j in 0:lx-1
                                byte = instructions[pc + 2 + j + 1]
                                immx |= UInt64(byte) << (8*j)
                            end
                            if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                                immx |= ~((UInt64(1) << (8*lx)) - 1)
                            end
                            immx_signed = reinterpret(Int64, immx)

                            println("  PC=0x$(string(pc, base=16)): load_ind_u64 r$ra = [r$rb + $immx_signed]")
                        else
                            println("  PC=0x$(string(pc, base=16)): opcode=$opcode")
                        end

                        pc += max(1, 1 + skip)
                    end
                end
                break
            end
        end
        break
    end
end
