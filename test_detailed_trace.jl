#!/usr/bin/env julia
# Detailed trace of instruction execution around the fault

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

                    println("=== DETAILED INSTRUCTION ANALYSIS ===\n")

                    # Show instruction bytes and mask for the critical region
                    println("PC range 0x478d - 0x47a0:\n")
                    for pc in 0x478d:0x47a0
                        if pc + 1 <= length(instructions)
                            is_opcode = opcode_mask[pc + 1]
                            byte = instructions[pc + 1]

                            # Calculate skip if this is an opcode
                            skip_val = "N/A"
                            if is_opcode
                                skip_val = string(PVM.skip_distance(opcode_mask, pc + 1))
                            end

                            println("  [0x$(string(pc, base=16))] $(is_opcode ? "OP" : "  ") byte=0x$(string(byte, base=16, pad=2)) skip=$skip_val")
                        end
                    end

                    # Now manually decode the instructions
                    println("\n=== MANUAL INSTRUCTION DECODE ===\n")

                    pc = 0x478d
                    println("Instruction at 0x$(string(pc, base=16)):")
                    println("  Opcode byte: 0x$(string(instructions[pc+1], base=16, pad=2))")
                    skip = PVM.skip_distance(opcode_mask, pc + 1)
                    println("  Skip distance: $skip")
                    println("  Register byte (offset +1): 0x$(string(instructions[pc+2], base=16, pad=2))")

                    # Decode register indices
                    reg_byte = instructions[pc+2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4
                    println("  Decoded: ra=$ra, rb=$rb")

                    # Decode immediate
                    lx = min(4, max(0, skip - 1))
                    println("  Immediate length (lx): $lx")
                    println("  Immediate bytes (starting at offset +2):")
                    for i in 0:lx-1
                        offset = pc + 2 + i
                        if offset + 1 <= length(instructions)
                            println("    [0x$(string(offset, base=16))] = 0x$(string(instructions[offset+1], base=16, pad=2))")
                        end
                    end

                    # Calculate immediate value
                    immx = UInt64(0)
                    for i in 0:lx-1
                        offset = pc + 2 + i
                        if offset + 1 <= length(instructions)
                            immx |= UInt64(instructions[offset+1]) << (8*i)
                        end
                    end
                    println("  Decoded immediate: 0x$(string(immx, base=16)) = $immx")

                    # Next PC
                    next_pc = pc + 1 + skip
                    println("  Next PC: 0x$(string(pc, base=16)) + 1 + $skip = 0x$(string(next_pc, base=16))")

                    # Check what's at 0x10910
                    println("\n=== MEMORY AT 0x10910 (ro_data offset 0x910) ===")
                    ro_offset = 0x910
                    if ro_offset + 8 <= length(ro_data)
                        bytes = ro_data[ro_offset+1:ro_offset+8]
                        val = UInt64(0)
                        for i in 0:7
                            val |= UInt64(bytes[i+1]) << (8*i)
                        end
                        println("  Value: 0x$(string(val, base=16, pad=16))")
                        println("  As ASCII: $(String([Char(b) for b in bytes if b >= 32 && b < 127]))")
                    end
                end
                break
            end
        end
        break
    end
end
