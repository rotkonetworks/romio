#!/usr/bin/env julia
include("src/pvm/pvm.jl")
using JSON3

# The LOG call was at PC=0x47d1 with opcode 0x0a (10)
# Let's find all occurrences of opcode 10 and also check what the ecalli opcode actually is

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
                    
                    # Check byte at PC=0x47d1
                    pc = 0x47d1
                    println("At PC=0x47d1:")
                    println("  opcode byte: 0x$(string(instructions[pc + 1], base=16)) = $(instructions[pc + 1])")
                    println("  skip: $(PVM.skip_distance(opcode_mask, pc + 1))")
                    
                    # Find all opcode 10 instructions
                    println("\nAll opcode 10 (ecalli) instructions:")
                    count = 0
                    for pc in 0:length(instructions)-1
                        if instructions[pc + 1] == 10  # opcode 10
                            skip = PVM.skip_distance(opcode_mask, pc + 1)
                            if skip > 0
                                # For ecalli, immediate is the host call id
                                imm = instructions[pc + 2]
                                count += 1
                                if count <= 30
                                    println("  PC=0x$(string(pc, base=16, pad=4)): ecalli $imm (skip=$skip)")
                                end
                            end
                        end
                    end
                    println("Total ecalli (opcode 10): $count")
                    
                    # Find FETCH (id=1) calls
                    println("\nLooking for FETCH (id=1) calls:")
                    for pc in 0:length(instructions)-1
                        if instructions[pc + 1] == 10
                            skip = PVM.skip_distance(opcode_mask, pc + 1)
                            if skip > 0 && instructions[pc + 2] == 1
                                println("  PC=0x$(string(pc, base=16, pad=4)): ecalli 1 (FETCH)")
                            end
                        end
                    end
                end
                break
            end
        end
        break
    end
end
