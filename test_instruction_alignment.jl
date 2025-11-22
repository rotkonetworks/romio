#!/usr/bin/env julia
# Check if we're executing the right instructions

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

                    println("=== INSTRUCTION STREAM VALIDATION ===\n")

                    # Check the opcode_mask bit pattern around our fault location
                    # Specifically check if the sequence 0x478d->0x4791->0x4792->0x4795 makes sense

                    println("Checking instruction sequence:")

                    pc = 0x478d
                    while pc <= 0x47a0
                        if pc + 1 <= length(opcode_mask)
                            is_opcode = opcode_mask[pc + 1]
                            byte = instructions[pc + 1]

                            if is_opcode
                                skip = PVM.skip_distance(opcode_mask, pc + 1)
                                next_pc = pc + 1 + skip
                                println("\n[PC 0x$(string(pc, base=16))] OPCODE=0x$(string(byte, base=16, pad=2)) skip=$skip → next=0x$(string(next_pc, base=16))")

                                # Show the immediate bytes
                                if skip > 0
                                    print("  Immediate/data bytes:")
                                    for i in 1:skip
                                        if pc + i + 1 <= length(instructions)
                                            print(" 0x$(string(instructions[pc + i + 1], base=16, pad=2))")
                                        end
                                    end
                                    println()
                                end

                                pc = next_pc
                            else
                                println("[PC 0x$(string(pc, base=16))] DATA byte=0x$(string(byte, base=16, pad=2))")
                                pc += 1
                            end
                        else
                            break
                        end
                    end

                    # Now trace what our PVM ACTUALLY executes
                    println("\n=== COMPARING WITH EXPECTED SEQUENCE ===")
                    println("Expected path based on mask:")
                    println("  0x478d (LOAD_IMM) → 0x4791 (fallthrough) → 0x4792 (BRANCH_LT_U) → 0x4795 (fall-through if not taken)")
                    println("\nIf mask is wrong, we might jump to wrong locations")
                end
                break
            end
        end
        break
    end
end
