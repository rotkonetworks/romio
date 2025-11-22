#!/usr/bin/env julia
# Check instruction at step 977 PC=0x329a

using JSON3
include("src/pvm/pvm.jl")

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                result = PVM.deblob(blob_bytes)
                if result !== nothing
                    instructions, opcode_mask, jump_table, ro_data, rw_data, stack_pages, stack_bytes = result

                    println("=== INSTRUCTION AT PC 0x329a (step 977) ===\n")

                    pc = 0x329a
                    opcode = instructions[pc+1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2))")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    reg_byte = instructions[pc+2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("Register byte: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra (r8), rb=$rb (r6)")

                    # Decode immediate
                    lx = min(4, max(0, skip - 1))
                    println("Immediate length (lx): $lx")

                    println("Immediate bytes:")
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        if byte_pos + 1 <= length(instructions)
                            byte = instructions[byte_pos+1]
                            println("  [0x$(string(byte_pos, base=16))] = 0x$(string(byte, base=16, pad=2))")
                        end
                    end

                    # Calculate immediate
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        if byte_pos + 1 <= length(instructions)
                            immx |= UInt64(instructions[byte_pos+1]) << (8*i)
                        end
                    end

                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end

                    println("\nDecoded immediate: 0x$(string(immx, base=16, pad=16)) = $immx")
                    println("As Int64: $(Int64(immx))")

                    # What address does this compute?
                    r6_value = 0x10918  # from the log
                    target_addr = r6_value + Int64(immx)
                    println("\nComputed address: 0x$(string(r6_value, base=16)) + $(Int64(immx)) = 0x$(string(target_addr, base=16))")

                    # What's at that address in ro_data?
                    if target_addr >= 0x10000 && target_addr + 7 < 0x10000 + length(ro_data)
                        offset = target_addr - 0x10000
                        bytes = ro_data[offset+1:offset+8]
                        value = reinterpret(UInt64, bytes)[1]
                        println("Value at 0x$(string(target_addr, base=16)) in ro_data: 0x$(string(value, base=16, pad=16))")
                        println("As ASCII: $(String([Char(b) for b in bytes if b >= 32 && b < 127]))")
                    end

                    # What SHOULD be at that address?
                    println("\n=== CHECKING IF THIS IS CORRECT ===")
                    println("If the program expects to load a valid pointer from 0x10910,")
                    println("then either:")
                    println("1. The blob has wrong data at offset 0x910, OR")
                    println("2. The program shouldn't be loading from this offset, OR")
                    println("3. The test pattern IS intentional and program should handle it differently")
                end
                break
            end
        end
        break
    end
end
