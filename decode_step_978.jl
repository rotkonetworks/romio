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

                    # Decode instruction at PC=0x329a (step 977) - this is where r8 gets bad value
                    pc = 0x329a
                    opcode = instructions[pc + 1]
                    skip = PVM.skip_distance(opcode_mask, pc + 1)

                    reg_byte = instructions[pc + 2]
                    ra = reg_byte & 0x0F
                    rb = reg_byte >> 4

                    lx = min(4, max(0, skip - 1))
                    immx = UInt64(0)
                    for i in 0:lx-1
                        byte = instructions[pc + 2 + i + 1]
                        immx |= UInt64(byte) << (8*i)
                    end
                    if lx > 0 && (immx >> (8*lx - 1)) & 1 == 1
                        immx |= ~((UInt64(1) << (8*lx)) - 1)
                    end
                    immx_signed = reinterpret(Int64, immx)

                    println("Step 977: PC=0x329a (where r8 gets bad value)")
                    println("  opcode=$opcode (load_ind_u64)")
                    println("  skip=$skip")
                    println("  ra=$ra (r$ra), rb=$rb (r$rb)")
                    println("  immediate=$immx_signed")
                    println("  Bytes: [$(join(["0x" * string(instructions[pc+i+1], base=16, pad=2) for i in 0:skip], " "))]")

                    # From trace: r8 = 0x114c2 before this instruction
                    # This instruction: r8 = load_u64(rb + immx_signed)
                    # So rb = 8, and we're loading from r8 + immx_signed
                    r8_before = 0x114c2  # from trace
                    addr = UInt32((r8_before + immx_signed) % 2^32)
                    println("\n  Before: r8 = 0x$(string(r8_before, base=16))")
                    println("  Load from: r$rb + $immx_signed = 0x$(string(addr, base=16, pad=8))")

                    # Check what's at that address in ro_data
                    if addr >= 0x10000 && addr < 0x10000 + length(ro_data)
                        offset = addr - 0x10000
                        value = UInt64(0)
                        for i in 0:7
                            if offset + i + 1 <= length(ro_data)
                                value |= UInt64(ro_data[offset + i + 1]) << (8*i)
                            end
                        end
                        println("\n  ro_data at offset 0x$(string(offset, base=16)) = 0x$(string(value, base=16))")

                        # Show bytes
                        bytes = [ro_data[offset + i + 1] for i in 0:7]
                        println("  Bytes: $(bytes)")
                        println("  As ASCII: $(String([bytes[i] >= 32 && bytes[i] <= 126 ? Char(bytes[i]) : '.' for i in 1:8]))")
                    end
                end
                break
            end
        end
        break
    end
end
