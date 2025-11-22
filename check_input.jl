#!/usr/bin/env julia
# Check that input buffer is correctly written

include("src/stf/accumulate.jl")

# Build test input
timeslot = UInt32(43)
service_id = UInt32(1729)
count = UInt32(1)

input = UInt8[]
append!(input, reinterpret(UInt8, [timeslot]))
append!(input, reinterpret(UInt8, [service_id]))
append!(input, reinterpret(UInt8, [count]))

println("Input buffer (12 bytes):")
for i in 1:12
    println("  offset $(i-1): 0x$(string(input[i], base=16, pad=2))")
end

println("\nExpected:")
println("  Timeslot: $(timeslot) = 0x$(string(timeslot, base=16, pad=8))")
println("  Service ID: $(service_id) = 0x$(string(service_id, base=16, pad=8))")
println("  Count: $(count) = 0x$(string(count, base=16, pad=8))")

# Verify parsing
parsed_timeslot = reinterpret(UInt32, input[1:4])[1]
parsed_service_id = reinterpret(UInt32, input[5:8])[1]
parsed_count = reinterpret(UInt32, input[9:12])[1]

println("\nParsed back:")
println("  Timeslot: $(parsed_timeslot)")
println("  Service ID: $(parsed_service_id)")
println("  Count: $(parsed_count)")
