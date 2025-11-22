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
                    
                    # Decode first 9 instructions
                    pc = jump_table[11]  # Entry point 10
                    for i in 1:9
                        if pc >= length(instructions) break end
                        
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)
                        
                        if skip == 0 break end
                        
                        bytes = instructions[(pc+1):min(pc+skip+1, length(instructions))]
                        
                        # Decode registers
                        reg_byte = instructions[pc + 2]
                        ra = reg_byte & 0x0F
                        rb = (reg_byte >> 4) & 0x0F
                        
                        name = "op=$opcode"
                        if opcode == 130
                            # load_ind_u64 ra=[rb+offset]
                            lx = min(4, max(0, skip - 1))
                            offset = Int64(0)
                            for j in 0:lx-1
                                byte = instructions[pc + 2 + j + 1]
                                offset |= Int64(byte) << (8*j)
                            end
                            if lx > 0 && (offset >> (8*lx - 1)) & 1 == 1
                                offset |= ~((Int64(1) << (8*lx)) - 1)
                            end
                            name = "load_ind_u64 r$ra = [r$rb + $offset]"
                        elseif opcode == 201
                            # sub_64 rd = ra - rb
                            rd = instructions[pc + 3] & 0x0F
                            name = "sub_64 r$rd = r$ra - r$rb"
                        elseif opcode == 200
                            rd = instructions[pc + 3] & 0x0F
                            name = "add_64 r$rd = r$ra + r$rb"
                        elseif opcode == 100
                            # load_u64 (load immediate)
                            lx = min(8, skip)
                            imm = UInt64(0)
                            for j in 0:lx-1
                                if pc + 1 + j < length(instructions)
                                    byte = instructions[pc + 1 + j + 1]
                                    imm |= UInt64(byte) << (8*j)
                                end
                            end
                            name = "load_u64 r$ra = $imm"
                        end
                        
                        println("$i. PC=0x$(string(pc, base=16)): $name (skip=$skip)")
                        pc += 1 + skip
                    end
                end
                break
            end
        end
        break
    end
end
