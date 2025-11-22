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
                    
                    # Decode branch at PC=0x43b (opcode 83 = branch_lt_u_imm)
                    pc = 0x43b
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    
                    println("Instruction at PC=0x$(string(pc, base=16)):")
                    println("  opcode: $opcode (branch_lt_u_imm)")
                    
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    lx = (reg_byte >> 4) & 0x07
                    ly = max(0, skip - lx - 1)
                    
                    # Decode immediate
                    immx = UInt64(0)
                    for j in 0:lx-1
                        if pc + 2 + j < length(instructions)
                            byte = instructions[pc + 2 + j + 1]
                            immx |= UInt64(byte) << (8*j)
                        end
                    end
                    
                    # Decode offset
                    immy = Int64(0)
                    for j in 0:ly-1
                        if pc + 2 + lx + j < length(instructions)
                            byte = instructions[pc + 2 + lx + j + 1]
                            immy |= Int64(byte) << (8*j)
                        end
                    end
                    if ly > 0 && (immy >> (8*ly - 1)) & 1 == 1
                        immy |= ~((Int64(1) << (8*ly)) - 1)
                    end
                    
                    target = pc + immy
                    
                    println("  ra: $ra (r$ra)")
                    println("  immx: $immx (compare value)")
                    println("  target: 0x$(string(target, base=16))")
                    println()
                    println("Semantics: if r$ra < $immx then jump to 0x$(string(target, base=16))")
                end
                break
            end
        end
        break
    end
end
