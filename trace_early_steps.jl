#!/usr/bin/env julia
# Trace the very early steps of accumulate execution to understand what it expects

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

                    # Entry point 10 = accumulate
                    start_pc = jump_table[11]  # Julia 1-indexed
                    println("Accumulate entry point: PC=0x$(string(start_pc, base=16))")
                    println()

                    # Decode first 20 instructions from entry point
                    println("First 20 instructions from entry point 10:")
                    pc = start_pc
                    for i in 1:20
                        if pc >= length(instructions)
                            break
                        end

                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)

                        # Get register bytes and immediate
                        reg_byte = skip >= 2 ? instructions[pc + 2] : 0
                        ra = reg_byte & 0x0F
                        rb = reg_byte >> 4

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

                        # Identify instruction type
                        instr_name = "op=$opcode"
                        if opcode == 130  # load_ind_u64
                            instr_name = "load_ind_u64 r$ra = [r$rb + $immx_signed]"
                        elseif opcode == 10  # ecalli
                            instr_name = "ecalli $immx_signed"
                        elseif opcode == 51  # add_imm
                            instr_name = "add_imm r$ra = r$rb + $immx_signed"
                        elseif opcode == 0
                            instr_name = "trap"
                        end

                        println("  PC=0x$(string(pc, base=16, pad=4)): $instr_name  (skip=$skip)")
                        pc += max(1, skip)
                    end
                end
                break
            end
        end
        break
    end
end
