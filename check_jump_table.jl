#!/usr/bin/env julia
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

                    println("Jump table ($(length(jump_table)) entries):")
                    for (i, pc) in enumerate(jump_table)
                        println("  [$i] (entry $(i-1)): PC = 0x$(string(pc, base=16)) ($pc)")
                    end
                    println()

                    # Show what entry points 0, 5, 10, 15 are
                    println("Standard entry points:")
                    for ep in [0, 5, 10, 15]
                        if ep + 1 <= length(jump_table)
                            pc = jump_table[ep + 1]
                            println("  Entry $ep: PC = 0x$(string(pc, base=16))")
                        else
                            println("  Entry $ep: NOT IN JUMP TABLE")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
