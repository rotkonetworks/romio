#!/usr/bin/env julia
# Check where 0x10908 actually points and what ro_data vs rw_data contain

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

                    println("Memory layout:")
                    println("  ro_data: 0x10000-0x$(string(0x10000 + length(ro_data) - 1, base=16)) ($(length(ro_data)) bytes)")
                    println("  rw_data: 0x20000-0x$(string(0x20000 + length(rw_data) - 1, base=16)) ($(length(rw_data)) bytes)")
                    println()

                    # The address 0x10908 = 0x10000 + 0x908
                    # offset 0x908 = 2312 in ro_data
                    println("Address 0x10908 is at ro_data offset 0x908 = $(0x908)")
                    println()

                    # What if the service expects to find config in rw_data at offset 0x908?
                    # That would be address 0x20908
                    println("If service expected config in rw_data:")
                    println("  Address would be 0x20000 + 0x908 = 0x20908")
                    println("  But rw_data only has $(length(rw_data)) bytes")
                    println()

                    # Check if maybe the program is computing addresses wrong
                    # 67840 = 0x10900 is the pointer it loads
                    # It then adds 8 to get 0x10908
                    println("Program loads pointer 67840 = 0x10900")
                    println("Then reads offset 8 to get address 0x10908")
                    println()

                    # Check what's at ro_data offsets around 0x900
                    println("ro_data structure at offset 0x900:")
                    for off in 0:15
                        addr = 0x900 + off * 8
                        if addr + 8 <= length(ro_data)
                            bytes = [ro_data[addr + i + 1] for i in 0:7]
                            val = reinterpret(UInt64, bytes)[1]
                            println("  0x$(string(addr, base=16, pad=3)): $(val) (0x$(string(val, base=16)))")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
