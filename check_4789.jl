#!/usr/bin/env julia
# Check instruction at PC 0x4789 (step 981)

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

                    println("=== INSTRUCTION AT PC 0x4789 (step 981) ===\n")
                    pc = 0x4789

                    opcode = instructions[pc + 1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode) - load_ind_u64")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("Register byte: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra (dest=r$ra), rb=$rb (base=r$rb)")

                    # Decode immediate
                    lx = min(4, max(0, skip - 1))
                    println("Immediate length (lx): $lx")

                    # Read immediate bytes
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        if byte_pos + 1 <= length(instructions)
                            byte_val = instructions[byte_pos + 1]
                            immx |= UInt64(byte_val) << (8*i)
                            println("  Immediate byte $i at [0x$(string(byte_pos, base=16))]: 0x$(string(byte_val, base=16, pad=2))")
                        end
                    end

                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end

                    println("\nDecoded immediate (immx): 0x$(string(immx, base=16, pad=16))")
                    println("As signed: $(Int64(immx))")

                    println("\nThis instruction loads from [r$rb + $(Int64(immx))] into r$ra")

                    # From trace: r7=4278058528 at step 981
                    if rb == 7
                        r7_value = 4278058528
                        target_addr = r7_value + Int64(immx)
                        println("\nr7 = $r7_value = 0x$(string(r7_value, base=16)) (from trace)")
                        println("Load address: r7 + $(Int64(immx)) = $(target_addr) = 0x$(string(target_addr, base=16))")

                        # Check if this is in ro_data or rw_data
                        if target_addr >= 0x10000 && target_addr + 7 < 0x10000 + length(ro_data)
                            offset = target_addr - 0x10000
                            bytes = ro_data[offset+1:offset+8]
                            value = reinterpret(UInt64, bytes)[1]
                            println("\nValue in ro_data at 0x$(string(target_addr, base=16)):")
                            println("  Hex: 0x$(string(value, base=16, pad=16))")
                            println("  Bytes: [$(join(["0x$(string(b, base=16, pad=2))" for b in bytes], ", "))]")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
