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

                    println("ro_data length: $(length(ro_data))")

                    # Check offset 0x14c2 (what 70850 = 0x114c2 points to)
                    offset = 0x14c2
                    if offset + 32 <= length(ro_data)
                        println("\nAt offset 0x$(string(offset, base=16)) (address 0x$(string(0x10000 + offset, base=16))):")

                        # Show 32 bytes of context
                        for o in 0:3
                            start = offset + o*8
                            bytes = [ro_data[start + i + 1] for i in 0:7]
                            ascii = String([bytes[i] >= 32 && bytes[i] <= 126 ? Char(bytes[i]) : '.' for i in 1:8])
                            println("  +$(o*8): $ascii  [$(join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))]")
                        end
                    end

                    # Also check what the TEST result payload offset might be
                    # The test payload is "0x82aa36" for this test
                    # Let me search for where this might be in the input or ro_data
                end
                break
            end
        end
        break
    end
end
