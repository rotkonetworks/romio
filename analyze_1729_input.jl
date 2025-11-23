# Analyze what service 1729 is checking
# Focus on the values around step 42

push!(LOAD_PATH, joinpath(@__DIR__, "src"))

include("src/stf/accumulate.jl")

# Load test
test_path = "jam-test-vectors/stf/accumulate/full/process_one_immediate_report-1.json"
tv = load_test_vector(test_path)

# Get service 1729
service_id = ServiceId(1729)
account = tv.pre_state.accounts[service_id]
service_code = account.preimages[account.code_hash]

# Parse the blob to get ro_data and rw_data
include("src/pvm/pvm.jl")
using .PVM

# Get program sections
parsed = PVM.deblob(service_code)
if parsed === nothing
    error("Failed to parse")
end
code, opcode_mask, jump_table = parsed

println("=== Program Analysis ===")
println("Code length: $(length(code))")
println("Jump table entries: $(length(jump_table))")
println("Entry point 5: 0x$(string(jump_table[6], base=16))")

# Check key addresses
println("\n=== Key Values ===")
println("0x10108 (step 4 r7): $(0x10108 - 0x10000) bytes into code")
println("0x11748 (step 5 r10): $(0x11748 - 0x10000) bytes into code")
println("0x117f8 (step 41 r8=71528): $(0x117f8 - 0x10000) bytes into code")

# Build input to check format
input_timeslot = UInt32(tv.input[:slot])
input_service_id = UInt32(1729)
input_count = UInt32(1)

input = UInt8[]
append!(input, reinterpret(UInt8, [input_timeslot]))
append!(input, reinterpret(UInt8, [input_service_id]))
append!(input, reinterpret(UInt8, [input_count]))

println("\n=== Input Buffer ===")
println("Bytes: $(bytes2hex(input))")
println("Parsed:")
println("  timeslot: $input_timeslot (0x$(string(input_timeslot, base=16)))")
println("  service_id: $input_service_id (0x$(string(input_service_id, base=16)))")
println("  count: $input_count (0x$(string(input_count, base=16)))")

# Check if there's an issue with how we decode the blob
# The service might expect something in rw_data

# Let's also check the ro_data content
println("\n=== Memory Layout ===")
println("ZONE_SIZE: 0x10000 (65536)")
println("Code at: 0x10000")
println("ro_data at: 0x10000 + $(length(code)) = 0x$(string(0x10000 + length(code), base=16))")

# Parse the blob header to get rw_data info
function parse_blob_sections(blob::Vector{UInt8})
    offset = 1

    # Skip version byte
    if blob[offset] != 0x00
        error("Bad version")
    end
    offset += 1

    # Parse lengths using varint
    function read_varint(data, off)
        first_byte = data[off]
        if first_byte < 128
            return (Int(first_byte), off + 1)
        end
        l = 256 - first_byte
        if l > 4
            error("Varint too large")
        end
        value = 0
        for i in 0:l-1
            value |= Int(data[off + 1 + i]) << (8 * i)
        end
        return (value, off + 1 + l)
    end

    # Read jump_table_length
    jump_len, offset = read_varint(blob, offset)

    # Read code_and_ro_data_length
    code_ro_len, offset = read_varint(blob, offset)

    # Read rw_data_length
    rw_len, offset = read_varint(blob, offset)

    # Read stack_size
    stack_size, offset = read_varint(blob, offset)

    println("Blob header:")
    println("  jump_table_length: $jump_len (entries)")
    println("  code_and_ro_data_length: $code_ro_len")
    println("  rw_data_length: $rw_len")
    println("  stack_size: $stack_size (pages)")

    return (jump_len, code_ro_len, rw_len, stack_size)
end

jump_len, code_ro_len, rw_len, stack_size = parse_blob_sections(service_code)

println("\n=== rw_data ===")
println("Length: $rw_len bytes")
println("Expected at: 0x20000")

# Find where rw_data is in the blob
# Skip: version (1) + varints for header + jump_table + code_and_ro_data + opcode_mask
# Then rw_data follows

# Actually, we should check what values are at the addresses the service is reading
# The service at step 7 loads timeslot (43) from input, so input is correct
# But something else is wrong

# Let me check what the service is doing at step 41-42
# r8 = 71528 at step 41, then r8 = 0 at step 42
# 71528 = 0x117f8, this is in code+ro_data area
# The service might be loading a value from there

code_ro_data_offset = 0x117f8 - 0x10000
if code_ro_data_offset < code_ro_len
    println("\n=== Address 0x117f8 (offset $code_ro_data_offset) ===")
    println("This is within code+ro_data region")
end
