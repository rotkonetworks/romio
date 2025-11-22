#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

# Enable step tracing in PVM
# We'll modify the execute function to trace each step

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
                    
                    # Simulate execution to find branches
                    pc = jump_table[11]  # Entry point 10
                    println("Starting at PC=0x$(string(pc, base=16))")
                    println("Tracing first 70 instructions to see branches:\n")
                    
                    for step in 1:70
                        if pc >= length(instructions)
                            println("PC beyond code!")
                            break
                        end
                        
                        opcode = instructions[pc + 1]
                        skip = PVM.skip_distance(opcode_mask, pc + 1)
                        
                        # Decode instruction for branches/jumps
                        name = "op=$opcode"
                        target = ""
                        
                        if opcode == 10  # ecalli
                            imm = instructions[pc + 2]
                            name = "ecalli $imm"
                            if imm == 100
                                name *= " (LOG)"
                            elseif imm == 1
                                name *= " (FETCH)"
                            end
                        elseif opcode in [40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]  # branches
                            # Decode branch target
                            lx = min(4, max(0, skip))
                            immx = UInt64(0)
                            for j in 0:lx-1
                                if pc + 1 + j < length(instructions)
                                    byte = instructions[pc + 1 + j + 1]
                                    immx |= UInt64(byte) << (8*j)
                                end
                            end
                            if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                                immx |= ~((UInt64(1) << (8*lx)) - 1)
                            end
                            target_pc = Int(pc) + Int(reinterpret(Int64, immx))
                            name = "branch → 0x$(string(target_pc, base=16, pad=4))"
                        elseif opcode == 7  # jump
                            lx = min(4, max(0, skip))
                            immx = UInt64(0)
                            for j in 0:lx-1
                                if pc + 1 + j < length(instructions)
                                    byte = instructions[pc + 1 + j + 1]
                                    immx |= UInt64(byte) << (8*j)
                                end
                            end
                            if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                                immx |= ~((UInt64(1) << (8*lx)) - 1)
                            end
                            target_pc = Int(pc) + Int(reinterpret(Int64, immx))
                            name = "JUMP → 0x$(string(target_pc, base=16, pad=4))"
                        end
                        
                        println("  $step. PC=0x$(string(pc, base=16, pad=4)): $name (skip=$skip)")
                        
                        # Move to next instruction (assume no branch taken for linear trace)
                        if skip == 0
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
