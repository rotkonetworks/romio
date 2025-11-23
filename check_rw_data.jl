# Check rw_data initialization for service 1729

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/test_vectors/loader.jl")
include("src/pvm/pvm.jl")
using .PVM

# Load test
test_path = "jam-test-vectors/stf/accumulate/full/process_one_immediate_report-1.json"
tv = load_test_vector(test_path)

service_id = ServiceId(1729)
account = tv.pre_state.accounts[service_id]
service_code = account.preimages[account.code_hash]

println("=== Checking RW Data for Service 1729 ===")
println("Code blob size: $(length(service_code)) bytes")

# Parse the blob header manually to get rw_data
function parse_blob_header(blob::Vector{UInt8})
    offset = 1

    # Check version
    if blob[offset] != 0x00 && blob[offset] != 0x05
        println("Version byte: $(blob[offset])")
    end
    offset += 1

    # Parse lengths using graypaper varint encoding
    function read_varint(data, off)
        first_byte = data[off]
        if first_byte == 0
            return (0, off + 1)
        elseif first_byte < 128
            return (Int(first_byte), off + 1)
        end
        l = 256 - first_byte
        value = 0
        for i in 0:l-1
            value |= Int(data[off + 1 + i]) << (8 * i)
        end
        return (value, off + 1 + l)
    end

    # Read jump_table_length (in entries)
    jump_len, offset = read_varint(blob, offset)

    # Read code_and_ro_data_length
    code_ro_len, offset = read_varint(blob, offset)

    # Read rw_data_length
    rw_len, offset = read_varint(blob, offset)

    # Read stack_size (in pages)
    stack_size, offset = read_varint(blob, offset)

    return (jump_len, code_ro_len, rw_len, stack_size, offset)
end

jump_len, code_ro_len, rw_len, stack_pages, header_end = parse_blob_header(service_code)

println("\nBlob structure:")
println("  Jump table entries: $jump_len")
println("  Code + ro_data length: $code_ro_len")
println("  RW data length: $rw_len")
println("  Stack pages: $stack_pages")
println("  Header ends at byte: $header_end")

# Calculate where each section is in the blob
jump_table_start = header_end
jump_table_bytes = jump_len * 4  # Each entry is 4 bytes

code_ro_start = jump_table_start + jump_table_bytes
code_start_in_blob = code_ro_start

# opcode_mask is ceil(code_ro_len / 8) bytes
mask_bytes = div(code_ro_len + 7, 8)
mask_start = code_start_in_blob + code_ro_len

rw_start = mask_start + mask_bytes

println("\nSection locations in blob:")
println("  Jump table: $jump_table_start - $(jump_table_start + jump_table_bytes - 1)")
println("  Code+ro_data: $code_start_in_blob - $(code_start_in_blob + code_ro_len - 1)")
println("  Opcode mask: $mask_start - $(mask_start + mask_bytes - 1)")
println("  RW data: $rw_start - $(rw_start + rw_len - 1)")

if rw_start + rw_len > length(service_code)
    println("  WARNING: RW data extends beyond blob!")
else
    # Show first few bytes of rw_data
    println("\nRW data first 32 bytes:")
    for i in 0:min(31, rw_len - 1)
        if i % 16 == 0
            print("  0x$(string(i, base=16, pad=4)): ")
        end
        print("$(string(service_code[rw_start + i], base=16, pad=2)) ")
        if i % 16 == 15
            println()
        end
    end
    println()
end

# Check what our PVM loads at 0x20000 (rw_data address)
println("\n=== Memory Layout ===")
println("RW data should be at: 0x20000")
println("RW data length: $rw_len bytes")

# Let me also check if there's something in the test vector's pre_state
# that indicates expected rw_data values
