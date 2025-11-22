#!/usr/bin/env julia
# Check instruction at PC 0x329d (step 978 where r8 gets test pattern)

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

                    println("=== INSTRUCTION AT PC 0x329d (step 978) ===\n")
                    pc = 0x329d

                    opcode = instructions[pc + 1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode) - load_ind_u64")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("Register byte: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra (r$ra), rb=$rb (r$rb)")

                    # Decode immediate
                    lx = min(4, max(0, skip - 1))
                    println("Immediate length (lx): $lx")

                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        if byte_pos + 1 <= length(instructions)
                            immx |= UInt64(instructions[byte_pos + 1]) << (8*i)
                        end
                    end

                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end

                    println("Decoded immediate: 0x$(string(immx, base=16, pad=16))")
                    println("As signed: $(Int64(immx))")

                    # From trace: r6 = 0x0000000000010918
                    r6_value = 0x10918
                    target_addr = r6_value + Int64(immx)

                    println("\nLoad from address: r$rb (0x$(string(r6_value, base=16))) + $(Int64(immx)) = 0x$(string(target_addr, base=16))")

                    # Check what's at that address in ro_data
                    if target_addr >= 0x10000 && target_addr + 7 < 0x10000 + length(ro_data)
                        offset = target_addr - 0x10000
                        bytes = ro_data[offset+1:offset+8]
                        value = reinterpret(UInt64, bytes)[1]
                        println("\nValue at memory address 0x$(string(target_addr, base=16)):")
                        println("  Hex: 0x$(string(value, base=16, pad=16))")
                        println("  ASCII: $(String([Char(b) for b in bytes if b >= 32 && b < 127]))")
                        println("  This is the test pattern!")
                    end
                end
                break
            end
        end
        break
    end
end
