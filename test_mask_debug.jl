#!/usr/bin/env julia
# Debug opcode_mask and skip_distance calculations

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

                    println("=== MASK DEBUGGING ===\n")

                    # Check the mask byte that covers 0x478d (offset 18317)
                    offset_478d = 0x478d
                    byte_idx_478d = div(offset_478d, 8) + 1
                    bit_idx_478d = offset_478d % 8
                    mask_byte_478d = blob_bytes[blob_bytes[1] == 0x00 ? 2 : 1]  # skip magic byte
                    # Actually need to find where mask_bytes start in the blob

                    # Let's examine what skip_distance returns at different locations
                    println("Testing skip_distance at various offsets:\n")

                    test_offsets = [0x478d, 0x478e, 0x478f, 0x4790, 0x4791, 0x4792, 0x4793]
                    for offset in test_offsets
                        if offset + 1 <= length(opcode_mask)
                            skip = PVM.skip_distance(opcode_mask, offset + 1)
                            is_opcode = opcode_mask[offset + 1]
                            byte = instructions[offset + 1]
                            println("  [0x$(string(offset, base=16))] opcode=$(is_opcode ? 1 : 0) byte=0x$(string(byte, base=16, pad=2)) skip=$skip")
                        end
                    end

                    # Now let's see what the actual mask bytes are
                    println("\nMask bytes around the problematic area:")
                    for offset in 0x4788:0x4798
                        if offset + 1 <= length(opcode_mask)
                            byte_idx = div(offset, 8) + 1
                            is_opcode = opcode_mask[offset + 1]
                            byte = instructions[offset + 1]
                            println("  [0x$(string(offset, base=16))] byte_idx=$byte_idx bit=$(offset%8) opcode=$(is_opcode ? 1 : 0) instr=0x$(string(byte, base=16, pad=2))")
                        end
                    end

                    # Check what instruction bytes we have around 0x478d
                    println("\nInstruction bytes around 0x478d:")
                    for i in 0x478d:0x4795
                        if i + 1 <= length(instructions)
                            byte = instructions[i + 1]
                            print("0x$(string(byte, base=16, pad=2)) ")
                        end
                    end
                    println()
                end
                break
            end
        end
        break
    end
end
