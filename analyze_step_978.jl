#!/usr/bin/env julia
# Analyze instruction at PC=0x329d (step 978) that loads test pattern

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

                    println("=== STEP 978: PC=0x329d, opcode=0x82 (load_ind_u64) ===\n")

                    pc = 0x329d
                    opcode = instructions[pc + 1]
                    println("Opcode: 0x$(string(opcode, base=16, pad=2)) ($opcode)")

                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("Skip: $skip")

                    # Show instruction bytes
                    println("\nInstruction bytes:")
                    for i in 0:min(skip, 10)
                        byte = instructions[pc + i + 1]
                        println("  [PC+$i] = 0x$(string(byte, base=16, pad=2))")
                    end

                    # Decode according to load_ind_u64 implementation
                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("\nRegister byte [PC+1]: 0x$(string(reg_byte, base=16, pad=2)) → ra=$ra, rb=$rb")

                    # Immediate length
                    lx = min(4, max(0, skip - 1))
                    println("\nlx (immediate length): $lx (from skip-1 = $skip-1)")

                    # Decode immediate
                    println("\nImmediate (starts at PC+2):")
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte_pos = pc + 2 + i
                        byte = instructions[byte_pos + 1]
                        immx |= UInt64(byte) << (8*i)
                        println("  [PC+$(2+i)] = 0x$(string(byte, base=16, pad=2))")
                    end
                    # Sign extend
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    println("  Decoded immx: $immx = 0x$(string(immx, base=16))")

                    # From trace: r10=72496 at step 977
                    r10_value = UInt64(72496)
                    println("\nExecution (from trace: r$(rb)=0x$(string(r10_value, base=16))):")
                    println("  addr ← r$rb + immx = $r10_value + $immx = $(r10_value + immx)")

                    addr = (r10_value + immx) % 2^32
                    println("  addr (mod 2^32) = $addr = 0x$(string(addr, base=16))")

                    # Check what's at this address in memory
                    # r7 should point to stack which contains ro_data base address
                    if addr >= 0x10000 && addr < 0x10000 + length(ro_data)
                        offset = addr - 0x10000
                        println("\n  Address is in ro_data at offset 0x$(string(offset, base=16))")
                        println("  Reading 8 bytes from ro_data[$(offset)]:")

                        val = UInt64(0)
                        for i in 0:7
                            if offset + i < length(ro_data)
                                byte = ro_data[offset + i + 1]
                                val |= UInt64(byte) << (8*i)
                                print("    [+$i] = 0x$(string(byte, base=16, pad=2))")
                                if byte >= 32 && byte <= 126
                                    println(" ('$(Char(byte))')")
                                else
                                    println()
                                end
                            end
                        end
                        println("  Combined value: 0x$(string(val, base=16, pad=16)) = $val")
                        println("  As ASCII: \"$(String([ro_data[offset + i + 1] for i in 0:7]))\"")
                    elseif addr >= 0x20000 && addr < 0x20000 + length(rw_data)
                        offset = addr - 0x20000
                        println("\n  Address is in rw_data at offset 0x$(string(offset, base=16))")
                    else
                        println("\n  Address not in ro_data or rw_data")
                        println("  Checking if it's a stack address...")
                        if addr >= r7_value - 1000 && addr <= r7_value + 1000
                            println("  Address is near stack pointer")
                        end
                    end
                end
                break
            end
        end
        break
    end
end
