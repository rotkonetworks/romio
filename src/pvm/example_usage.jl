#!/usr/bin/env julia

# Example of using the PVM interpreter

include("pvm.jl")
using .PVM

# Method 1: Execute a PVM binary file directly
function run_pvm_file(filename)
    # Read the binary
    data = read(filename)

    # Extract code (this is simplified - real format parsing needed)
    code_offset = 0x40
    code_length = 25
    code = data[code_offset+1:code_offset+code_length]

    # Create bitmask for instruction positions
    bitmask = BitVector([1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0])

    # Create blob
    blob = UInt8[]
    push!(blob, 0)  # No jump table
    push!(blob, 1)  # Jump size
    push!(blob, code_length)  # Code length
    append!(blob, code)
    for bit in bitmask
        push!(blob, UInt8(bit))
    end

    # Execute with empty input and 10000 gas
    status, output, gas_used = PVM.execute(blob, UInt8[], UInt64(10000))

    println("Status: $status")
    println("Gas used: $gas_used")

    return status, output
end

# Method 2: Create and run custom PVM code
function run_custom_code()
    # Create simple program: load two numbers and add them
    instructions = UInt8[
        0x33, 0x00, 30, 0, 0, 0,      # load_imm r0, 30
        0x33, 0x10, 12, 0, 0, 0,      # load_imm r1, 12
        0xBE, 0x10, 0x20,              # add_32 r2 = r0 + r1
        0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
    ]

    # Create opcode mask
    mask = BitVector([
        1, 0, 0, 0, 0, 0,  # load_imm
        1, 0, 0, 0, 0, 0,  # load_imm
        1, 0, 0,           # add
        1, 0, 0, 0, 0, 0   # halt
    ])

    # Create blob
    blob = UInt8[]
    push!(blob, 0)  # No jump table
    push!(blob, 1)  # Jump size
    push!(blob, length(instructions))
    append!(blob, instructions)
    for bit in mask
        push!(blob, UInt8(bit))
    end

    # Decode and execute step by step
    result = PVM.deblob(blob)
    if result !== nothing
        instructions, opcode_mask, jump_table = result

        # Create state
        state = PVM.PVMState(
            0, Int64(100), zeros(UInt64, 13),
            PVM.Memory(), :continue,
            instructions, opcode_mask, jump_table
        )

        # Execute steps
        println("Executing custom program...")
        steps = 0
        while state.status == :continue && steps < 10
            PVM.step!(state)
            steps += 1
        end

        println("Result in r2: $(state.registers[3])")
        println("Status: $(state.status)")
    end
end

# Method 3: Run with specific register values
function run_with_args(a0_val, a1_val)
    # Load the hello-world example
    data = read(expanduser("~/rotko/polkavm/guest-programs/output/example-hello-world.polkavm"))

    code_offset = 0x40
    code_length = 25
    code = data[code_offset+1:code_offset+code_length]
    bitmask = BitVector([1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0])

    # Create blob
    blob = UInt8[]
    push!(blob, 0)
    push!(blob, 1)
    push!(blob, code_length)
    append!(blob, code)
    for bit in bitmask
        push!(blob, UInt8(bit))
    end

    # Decode
    result = PVM.deblob(blob)
    if result !== nothing
        instructions, opcode_mask, jump_table = result

        # Create state with custom register values
        state = PVM.PVMState(
            0, Int64(10000), zeros(UInt64, 13),
            PVM.Memory(), :continue,
            instructions, opcode_mask, jump_table
        )

        # Set up registers
        state.registers[8+1] = a0_val  # a0
        state.registers[9+1] = a1_val  # a1
        state.registers[2+1] = 0x20000 # SP

        # Set up memory
        for page_idx in 0x1C:0x22
            state.memory.access[page_idx + 1] = PVM.WRITE
        end

        println("Running with a0=$a0_val, a1=$a1_val")

        # Execute
        for i in 1:20
            if state.status != :continue
                break
            end

            PVM.step!(state)

            # Handle host calls
            if state.status == :host
                println("Host call triggered, returning 3")
                state.registers[8+1] = 3
                state.status = :continue
            end
        end

        println("Result: a0 = $(state.registers[8+1])")
        return state.registers[8+1]
    end
end

# Run examples
println("=== Example 1: Run PVM binary file ===")
# run_pvm_file(expanduser("~/rotko/polkavm/guest-programs/output/example-hello-world.polkavm"))

println("\n=== Example 2: Custom code ===")
run_custom_code()

println("\n=== Example 3: Run with different arguments ===")
result1 = run_with_args(10, 20)  # Should return 10 + 20 + 3 = 33
result2 = run_with_args(100, 200) # Should return 100 + 200 + 3 = 303