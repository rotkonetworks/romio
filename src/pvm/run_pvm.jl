# Run the actual PVM binary using our interpreter
include("pvm.jl")
using .PVM

# Read the binary file
data = read(expanduser("~/rotko/polkavm/guest-programs/output/example-hello-world.polkavm"))
println("File size: $(length(data)) bytes")

# The actual bytecode appears to be at the end
# Based on the disassembly, we have 25 bytes of code

# Looking at the hex dump, the code starts at offset 0x40
code_offset = 0x40
code_length = 25

if code_offset + code_length <= length(data)
    code = data[code_offset+1:code_offset+code_length]
    println("Code bytes ($(length(code))): ")
    for (i, byte) in enumerate(code)
        print("0x$(string(byte, base=16, pad=2)) ")
        if i % 8 == 0
            println()
        end
    end
    println()

    # Create a bitmask based on the disassembly
    # Instructions are at: 0, 3, 6, 8, 11, 12, 15, 18, 20, 23
    bitmask = BitVector(zeros(Bool, code_length))
    for pos in [0, 3, 6, 8, 11, 12, 15, 18, 20, 23]
        if pos < code_length
            bitmask[pos + 1] = true
        end
    end

    println("\nBitmask: $bitmask")

    # Try to create a simple blob for our interpreter
    blob = UInt8[]

    # Header
    push!(blob, 0)  # No jump table
    push!(blob, 1)  # Jump size
    push!(blob, code_length)  # Code length

    # Code
    append!(blob, code)

    # Bitmask as bytes
    for bit in bitmask
        push!(blob, UInt8(bit))
    end

    println("\nCreated blob: $(length(blob)) bytes")

    # Decode
    result = PVM.deblob(blob)
    if result !== nothing
        instructions, opcode_mask, jump_table = result
        println("Decoded successfully!")
        println("Instructions: $(length(instructions)) bytes")
        println("Jump table: $(length(jump_table)) entries")

        # Create state
        state = PVM.PVMState(
            0, Int64(10000), zeros(UInt64, 13),
            PVM.Memory(), :continue,
            instructions, opcode_mask, jump_table
        )

        # Initialize registers for the function
        # According to disassembly:
        # a0 and a1 are the input arguments
        # Julia is 1-indexed, so register N is at state.registers[N+1]
        state.registers[8+1] = 5   # a0 = 5 (register 8)
        state.registers[9+1] = 7   # a1 = 7 (register 9)
        state.registers[2+1] = 0x20000  # SP - stack pointer (register 2, above forbidden zone)

        # Allocate stack memory
        # Stack will be around 0x1fff8 after sp -= 8
        # That's page 31 (0x1F), so allocate pages around there
        for page_idx in 0x1C:0x22  # Allocate pages for stack
            state.memory.access[page_idx + 1] = PVM.WRITE  # Julia 1-indexed
        end

        println("\nInitial state:")
        println("  a0 = $(state.registers[8+1])")
        println("  a1 = $(state.registers[9+1])")
        println("  sp = $(state.registers[2+1])")

        # Execute some instructions
        println("\nExecuting...")
        for i in 1:10
            if state.status != :continue
                break
            end

            println("\nStep $i:")
            println("  PC: $(state.pc)")

            if state.pc < length(instructions) && opcode_mask[state.pc + 1]
                opcode = instructions[state.pc + 1]
                skip = PVM.skip_distance(opcode_mask, state.pc + 1)
                println("  Opcode: 0x$(string(opcode, base=16, pad=2)), skip=$skip")
                # Show next few bytes for context
                for j in 0:min(skip, 3)
                    if state.pc + 1 + j < length(instructions)
                        print(" $(string(instructions[state.pc + 1 + j + 1], base=16, pad=2))")
                    end
                end
                println()
            end

            PVM.step!(state)

            println("  Status: $(state.status)")
            if state.status == :host
                println("  Host call triggered!")
                # Simulate returning value 3 from get_third_number
                state.registers[8+1] = 3  # Return value in a0 (register 8)
                state.status = :continue
            end
        end

        println("\nFinal result:")
        println("  a0 = $(state.registers[8+1]) (should be 5 + 7 + 3 = 15)")
        println("  Status: $(state.status)")
    else
        println("Failed to decode!")
    end
else
    println("Invalid offsets for code extraction")
end