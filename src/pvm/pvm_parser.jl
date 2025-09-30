# Parser for PVM binary format

struct PVMProgram
    magic::Vector{UInt8}          # "PVM\0"
    version::UInt8
    ro_data::Vector{UInt8}
    rw_data::Vector{UInt8}
    stack_size::UInt32
    exports::Vector{Tuple{String, UInt32}}  # name, offset
    imports::Vector{String}
    jump_table::Vector{UInt32}
    code::Vector{UInt8}
    bitmask::BitVector
end

function read_varint(data::Vector{UInt8}, offset::Int)
    val = UInt32(0)
    shift = 0
    idx = offset

    while idx <= length(data)
        byte = data[idx]
        val |= UInt32(byte & 0x7F) << shift
        idx += 1
        if (byte & 0x80) == 0
            break
        end
        shift += 7
    end

    return (val, idx)
end

function parse_pvm(filename::String)
    data = read(filename)

    # Check magic
    if length(data) < 4 || data[1:3] != UInt8['P', 'V', 'M']
        error("Not a PVM file")
    end

    println("File size: $(length(data)) bytes")
    println("First 16 bytes: $(data[1:min(16, end)])")

    offset = 5  # Skip "PVM\0" and version

    # Read sections
    while offset < length(data)
        if offset + 1 > length(data)
            break
        end

        section_id = data[offset]
        offset += 1

        if section_id == 0x01  # Jump table
            count, offset = read_varint(data, offset)
            println("Jump table entries: $count")

            # Skip for now
            for i in 1:count
                target, offset = read_varint(data, offset)
                println("  Jump $i: $target")
            end

        elseif section_id == 0x04  # Imports
            count, offset = read_varint(data, offset)
            println("Imports: $count")

            for i in 1:count
                # Read index
                idx, offset = read_varint(data, offset)
                # Read name length
                name_len, offset = read_varint(data, offset)
                # Read name
                name = String(data[offset:offset+name_len-1])
                offset += name_len
                println("  Import $idx: $name")
            end

        elseif section_id == 0x05  # Exports
            count, offset = read_varint(data, offset)
            println("Exports: $count")

            for i in 1:count
                # Read index
                idx, offset = read_varint(data, offset)
                # Read offset
                export_offset, offset = read_varint(data, offset)
                # Read name length
                name_len, offset = read_varint(data, offset)
                # Read name
                name = String(data[offset:offset+name_len-1])
                offset += name_len
                println("  Export $idx @ $export_offset: $name")
            end

        elseif section_id == 0x06  # Code and bitmask
            code_len, offset = read_varint(data, offset)
            println("Code length: $code_len")

            # Skip info byte
            offset += 1

            # Read code
            code = data[offset:offset+code_len-1]
            offset += code_len
            println("Code bytes: $(length(code))")

            # Read bitmask - compact format
            bitmask_bytes = div(code_len + 7, 8)
            if offset + bitmask_bytes <= length(data)
                mask_data = data[offset:offset+bitmask_bytes-1]
                offset += bitmask_bytes

                # Convert to BitVector
                bitmask = BitVector(undef, code_len)
                for i in 1:code_len
                    byte_idx = div(i-1, 8) + 1
                    bit_idx = mod(i-1, 8)
                    if byte_idx <= length(mask_data)
                        bitmask[i] = (mask_data[byte_idx] >> bit_idx) & 1
                    end
                end

                println("Bitmask length: $(length(bitmask))")

                # Show first few instructions
                println("\nFirst instructions:")
                pc = 0
                for _ in 1:min(10, code_len)
                    if pc >= code_len
                        break
                    end

                    if bitmask[pc + 1]
                        opcode = code[pc + 1]
                        println("  PC $pc: opcode 0x$(string(opcode, base=16, pad=2))")
                    end
                    pc += 1
                end

                return (code, bitmask)
            end

        else
            println("Unknown section: 0x$(string(section_id, base=16))")
            break
        end
    end

    return nothing
end

# Test with the example
println("Parsing example-hello-world.polkavm:")
result = parse_pvm(expanduser("~/rotko/polkavm/guest-programs/output/example-hello-world.polkavm"))

if result !== nothing
    code, bitmask = result
    println("\nReady for execution!")
    println("Code: $(length(code)) bytes")
    println("Opcode positions: $(sum(bitmask))")
end