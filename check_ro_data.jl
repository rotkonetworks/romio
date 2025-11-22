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

                    println("ro_data length: $(length(ro_data)) bytes")
                    println("rw_data length: $(length(rw_data)) bytes")
                    println()

                    # Check offsets around 0x900
                    println("ro_data around offset 0x900:")
                    for base_off in [0x900, 0x908, 0x910, 0x918]
                        if base_off + 8 <= length(ro_data)
                            bytes = [ro_data[base_off + i + 1] for i in 0:7]
                            val_u64 = reinterpret(UInt64, bytes)[1]
                            println("  0x$(string(base_off, base=16)): 0x$(string(val_u64, base=16, pad=16)) ($val_u64)")
                        end
                    end

                    println()
                    println("Check what's around error string offset 0x14c2:")
                    # The error string "Protocol parameters are invalid" starts at 0x114c2 = 0x10000 + 0x14c2
                    base_off = 0x14c2
                    if base_off + 40 <= length(ro_data)
                        # Print the string
                        str_bytes = ro_data[(base_off+1):min(base_off+100, length(ro_data))]
                        # Find null terminator
                        null_pos = findfirst(x -> x == 0, str_bytes)
                        if null_pos !== nothing
                            str_bytes = str_bytes[1:null_pos-1]
                        end
                        println("  String at 0x$(string(base_off, base=16)): \"$(String(str_bytes))\"")
                    end

                    println()
                    # Check rw_data
                    println("rw_data content (first 64 bytes):")
                    for i in 0:7
                        if i*8 + 8 <= length(rw_data)
                            bytes = [rw_data[i*8 + j + 1] for j in 0:7]
                            val_u64 = reinterpret(UInt64, bytes)[1]
                            println("  0x$(string(i*8, base=16, pad=2)): 0x$(string(val_u64, base=16, pad=16)) ($val_u64)")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
