#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

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

                    # Entry point 10 = accumulate
                    start_pc = jump_table[11]  # Julia 1-indexed
                    println("Service 1729 accumulate entry point: PC=0x$(string(start_pc, base=16))")
                    println("Code length: $(length(instructions)) bytes")
                    println("Jump table: $(length(jump_table)) entries")
                    println()

                    # Show first 10 instructions from entry point
                    println("First 10 instructions from entry point 10:")
                    pc = start_pc
                    for i in 1:10
                        if pc >= length(instructions)
                            break
                        end

                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        if skip > 0
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

                            # Instruction name
                            name = "op=$opcode"
                            if opcode == 130
                                name = "load_ind_u64 r$ra=[r$rb+$immx_signed]"
                            elseif opcode == 149
                                name = "store_ind_u64 [r$rb+$immx_signed]=r$ra"
                            elseif opcode == 51
                                name = "add_imm r$ra = r$rb + $immx_signed"
                            elseif opcode == 4
                                name = "move_reg r$ra = r$rb"
                            elseif opcode == 40
                                name = "branch"
                            end

                            println("  $i. PC=0x$(string(pc, base=16, pad=4)): $name (skip=$skip)")
                        else
                            println("  $i. PC=0x$(string(pc, base=16, pad=4)): skip=0 (not opcode)")
                            break
                        end
                        pc += 1 + skip
                    end
                end
                break
            end
        end
        break
    end
end
