# PolkaVM Blob Parser
# Parses .polkavm binary format (PVM\0 magic header)
#
# Format reference: polkavm-common/src/program.rs

module PolkaVMBlob

export parse_polkavm_blob, PolkaVMProgram, PolkaVMExport, get_opcode_mask, find_export

# Section types
const SECTION_MEMORY_CONFIG = 0x01
const SECTION_RO_DATA = 0x02
const SECTION_RW_DATA = 0x03
const SECTION_IMPORTS = 0x04
const SECTION_EXPORTS = 0x05
const SECTION_CODE_AND_JUMP_TABLE = 0x06
const SECTION_OPT_DEBUG_STRINGS = 0x80
const SECTION_OPT_DEBUG_LINE_PROGRAMS = 0x81
const SECTION_OPT_DEBUG_LINE_PROGRAM_RANGES = 0x82
const SECTION_END_OF_FILE = 0x00

const BLOB_MAGIC = UInt8[0x50, 0x56, 0x4d, 0x00]  # "PVM\0"
const BLOB_LEN_SIZE = 8

struct PolkaVMExport
    name::String
    pc::UInt32
end

struct PolkaVMProgram
    is_64_bit::Bool
    ro_data_size::UInt32
    rw_data_size::UInt32
    stack_size::UInt32
    ro_data::Vector{UInt8}
    rw_data::Vector{UInt8}
    code::Vector{UInt8}
    bitmask::Vector{UInt8}
    jump_table::Vector{UInt32}
    jump_table_entry_size::UInt8
    imports::Vector{Tuple{UInt32, String}}  # (index, name)
    exports::Vector{PolkaVMExport}
end

# Read PolkaVM varint format
# Format: first byte determines length based on leading 1 bits
#   0xxxxxxx = 7-bit value (length 1)
#   10xxxxxx + 1 byte = 14-bit value (length 2)
#   110xxxxx + 2 bytes = 21-bit value (length 3)
#   1110xxxx + 3 bytes = 28-bit value (length 4)
#   11110000 + 4 bytes = 32-bit value (length 5)
function read_varint(data::Vector{UInt8}, offset::Int)
    if offset > length(data)
        error("Unexpected end of data at offset $offset")
    end

    first_byte = data[offset]

    # Count leading 1 bits to determine length
    leading_ones = leading_zeros(~first_byte)

    if leading_ones == 0
        # 0xxxxxxx - 7-bit value
        return (UInt32(first_byte), offset + 1)
    elseif leading_ones == 1
        # 10xxxxxx + 1 byte
        if offset + 1 > length(data)
            error("Unexpected end of data")
        end
        upper = UInt32(first_byte & 0x3f) << 8
        lower = UInt32(data[offset + 1])
        return (upper | lower, offset + 2)
    elseif leading_ones == 2
        # 110xxxxx + 2 bytes
        if offset + 2 > length(data)
            error("Unexpected end of data")
        end
        upper = UInt32(first_byte & 0x1f) << 16
        lower = UInt32(data[offset + 1]) | (UInt32(data[offset + 2]) << 8)
        return (upper | lower, offset + 3)
    elseif leading_ones == 3
        # 1110xxxx + 3 bytes
        if offset + 3 > length(data)
            error("Unexpected end of data")
        end
        upper = UInt32(first_byte & 0x0f) << 24
        lower = UInt32(data[offset + 1]) | (UInt32(data[offset + 2]) << 8) | (UInt32(data[offset + 3]) << 16)
        return (upper | lower, offset + 4)
    else
        # 11110000 + 4 bytes
        if offset + 4 > length(data)
            error("Unexpected end of data")
        end
        val = UInt32(data[offset + 1]) | (UInt32(data[offset + 2]) << 8) |
              (UInt32(data[offset + 3]) << 16) | (UInt32(data[offset + 4]) << 24)
        return (val, offset + 5)
    end
end

function parse_polkavm_blob(blob::Vector{UInt8})
    # Check magic header
    if length(blob) < 4 || blob[1:4] != BLOB_MAGIC
        error("Invalid .polkavm blob: missing magic header")
    end

    offset = 5  # After magic (1-indexed)

    # Read version byte
    if offset > length(blob)
        error("Unexpected end of blob")
    end
    version = blob[offset]
    offset += 1

    # Determine ISA from version
    is_64_bit = version >= 2  # Version 1 = 32-bit, Version 2+ = 64-bit

    # Skip blob length (8 bytes)
    offset += BLOB_LEN_SIZE

    # Initialize program data
    ro_data_size = UInt32(0)
    rw_data_size = UInt32(0)
    stack_size = UInt32(0)
    ro_data = UInt8[]
    rw_data = UInt8[]
    code = UInt8[]
    bitmask = UInt8[]
    jump_table = UInt32[]
    jump_table_entry_size = UInt8(0)
    imports = Tuple{UInt32, String}[]
    exports = PolkaVMExport[]

    # Parse sections
    while offset <= length(blob)
        # Read section type
        section_type = blob[offset]
        offset += 1

        if section_type == SECTION_END_OF_FILE
            break
        end

        # Read section length
        section_len, offset = read_varint(blob, offset)
        section_start = offset
        section_end = offset + Int(section_len)

        if section_end > length(blob) + 1
            error("Section extends beyond blob: section_end=$section_end, blob_len=$(length(blob))")
        end

        if section_type == SECTION_MEMORY_CONFIG
            ro_data_size, offset = read_varint(blob, offset)
            rw_data_size, offset = read_varint(blob, offset)
            stack_size, offset = read_varint(blob, offset)

        elseif section_type == SECTION_RO_DATA
            if section_len > 0
                ro_data = blob[offset:offset+Int(section_len)-1]
            end
            offset = section_end

        elseif section_type == SECTION_RW_DATA
            if section_len > 0
                rw_data = blob[offset:offset+Int(section_len)-1]
            end
            offset = section_end

        elseif section_type == SECTION_IMPORTS
            # First read import count
            import_count, offset = read_varint(blob, offset)

            # Read import offsets (4 bytes each)
            import_offsets = UInt32[]
            for _ in 1:import_count
                if offset + 3 > length(blob)
                    error("Unexpected end reading import offsets")
                end
                off = UInt32(blob[offset]) | (UInt32(blob[offset+1]) << 8) |
                      (UInt32(blob[offset+2]) << 16) | (UInt32(blob[offset+3]) << 24)
                push!(import_offsets, off)
                offset += 4
            end

            # Read import symbols (rest of section)
            symbols_data = blob[offset:section_end-1]
            offset = section_end

            # Parse symbol names from packed data
            sym_offset = 1
            for (i, imp_off) in enumerate(import_offsets)
                # Find null terminator or next offset
                name_end = sym_offset
                while name_end <= length(symbols_data) && symbols_data[name_end] != 0x00
                    name_end += 1
                end
                if sym_offset <= length(symbols_data)
                    name = String(symbols_data[sym_offset:name_end-1])
                    push!(imports, (imp_off, name))
                end
                sym_offset = name_end + 1
            end

        elseif section_type == SECTION_EXPORTS
            # Parse exports - first read count
            export_count, offset = read_varint(blob, offset)
            for _ in 1:export_count
                # Read PC
                pc, offset = read_varint(blob, offset)
                # Read name length
                name_len, offset = read_varint(blob, offset)
                # Read name
                if offset + Int(name_len) - 1 > length(blob)
                    error("Export name extends beyond blob")
                end
                name = String(blob[offset:offset+Int(name_len)-1])
                offset += Int(name_len)
                push!(exports, PolkaVMExport(name, UInt32(pc)))
            end
            offset = section_end

        elseif section_type == SECTION_CODE_AND_JUMP_TABLE
            # Parse code and jump table section
            # Order: jt_count, jt_entry_size, code_len, JUMP_TABLE, CODE, BITMASK
            jt_entry_count, offset = read_varint(blob, offset)

            # Read jump table entry size (1 byte)
            jump_table_entry_size = blob[offset]
            offset += 1

            # Read code length
            code_len, offset = read_varint(blob, offset)

            # Read jump table FIRST (before code!)
            if jt_entry_count > 0 && jump_table_entry_size > 0
                entry_size = Int(jump_table_entry_size)
                for _ in 1:jt_entry_count
                    if offset + entry_size - 1 > length(blob)
                        break
                    end
                    val = UInt32(0)
                    for j in 0:entry_size-1
                        val |= UInt32(blob[offset + j]) << (8 * j)
                    end
                    push!(jump_table, val)
                    offset += entry_size
                end
            end

            # Read code SECOND
            if code_len > 0
                code = blob[offset:offset+Int(code_len)-1]
                offset += Int(code_len)
            end

            # Read bitmask THIRD (rest of section)
            bitmask_len = div(Int(code_len) + 7, 8)
            if bitmask_len > 0 && offset + bitmask_len - 1 <= length(blob)
                bitmask = blob[offset:offset+bitmask_len-1]
                offset += bitmask_len
            end

        elseif (section_type & 0x80) != 0
            # Optional section - skip
            offset = section_end
        else
            # Unknown required section
            error("Unknown required section type: $section_type")
        end
    end

    return PolkaVMProgram(
        is_64_bit,
        ro_data_size,
        rw_data_size,
        stack_size,
        ro_data,
        rw_data,
        code,
        bitmask,
        jump_table,
        jump_table_entry_size,
        imports,
        exports
    )
end

# Convert bitmask bytes to BitVector
function get_opcode_mask(program::PolkaVMProgram)
    code_len = length(program.code)
    mask = BitVector(undef, code_len)
    for i in 0:code_len-1
        byte_idx = div(i, 8) + 1
        bit_idx = i % 8
        if byte_idx <= length(program.bitmask)
            mask[i+1] = (program.bitmask[byte_idx] & (1 << bit_idx)) != 0
        else
            mask[i+1] = false
        end
    end
    return mask
end

# Find export by name, returns PC or nothing
function find_export(program::PolkaVMProgram, name::String)
    for exp in program.exports
        if exp.name == name
            return exp.pc
        end
    end
    return nothing
end

end # module
