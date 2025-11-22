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

                    # Check ro_data at offset 0x910 (where r6-8 points)
                    offset = 0x910
                    println("ro_data at offset 0x$(string(offset, base=16)):")

                    value = UInt64(0)
                    for i in 0:7
                        if offset + i + 1 <= length(ro_data)
                            value |= UInt64(ro_data[offset + i + 1]) << (8*i)
                        end
                    end
                    println("  Value: 0x$(string(value, base=16))")

                    bytes = [ro_data[offset + i + 1] for i in 0:7]
                    println("  Bytes: $(bytes)")
                    println("  As ASCII: $(String([bytes[i] >= 32 && bytes[i] <= 126 ? Char(bytes[i]) : '.' for i in 1:8]))")
                    println("  As hex string: $(join(["0x$(string(b, base=16, pad=2))" for b in bytes], " "))")

                    # Show context around 0x910
                    println("\nContext around offset 0x910:")
                    for o in [0x900, 0x908, 0x910, 0x918, 0x920]
                        if o + 8 <= length(ro_data)
                            val = UInt64(0)
                            for i in 0:7
                                val |= UInt64(ro_data[o + i + 1]) << (8*i)
                            end
                            bytes = [ro_data[o + i + 1] for i in 0:7]
                            ascii = String([bytes[i] >= 32 && bytes[i] <= 126 ? Char(bytes[i]) : '.' for i in 1:8])
                            println("  0x$(string(o, base=16, pad=4)): $ascii")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
