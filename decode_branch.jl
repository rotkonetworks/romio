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
                    
                    # Decode branch_ne_imm at PC=0x372
                    pc = 0x372
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    
                    println("Instruction at PC=0x$(string(pc, base=16)):")
                    println("  opcode: $opcode (branch_ne_imm)")
                    println("  skip: $skip")
                    
                    # Raw bytes
                    bytes = instructions[(pc+1):min(pc+6, length(instructions))]
                    println("  bytes: $(join(["0x$(string(b, base=16, pad=2))" for b in bytes], ", "))")
                    
                    # Decode ra and lx
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F  # Low nibble
                    lx_nibble = (reg_byte >> 4) & 0x07  # Bits 4-6
                    lx = Int(min(4, lx_nibble))
                    ly = max(0, skip - lx - 1)
                    
                    println("  ra: $ra (r$ra)")
                    println("  lx: $lx, ly: $ly")
                    
                    # Decode immx (value to compare against)
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
                    
                    # Decode immy (branch offset)
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
                    
                    println("  immx: $immx (compare value)")
                    println("  immy: $immy (offset)")
                    println("  target: 0x$(string(target, base=16))")
                    println()
                    println("Semantics: if r$ra != $immx then jump to 0x$(string(target, base=16))")
                end
                break
            end
        end
        break
    end
end
