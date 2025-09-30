# Comprehensive test suite for PVM interpreter
# Tests all instructions, memory safety, and edge cases

include("secure_pvm.jl")
using .SecurePVM
using Test

# Helper to create program blob
function create_program(instructions::Vector{UInt8}, opcode_mask::BitVector, jump_table::Vector{UInt32} = UInt32[])
    blob = UInt8[]

    # Jump count
    push!(blob, length(jump_table))

    # Jump size (4 bytes per entry)
    push!(blob, 4)

    # Code length
    push!(blob, length(instructions))

    # Jump table entries
    for target in jump_table
        for i in 0:3
            push!(blob, UInt8((target >> (8*i)) & 0xFF))
        end
    end

    # Instructions
    append!(blob, instructions)

    # Opcode mask
    for bit in opcode_mask
        push!(blob, UInt8(bit))
    end

    return blob
end

@testset "PVM Interpreter Tests" begin

    @testset "Basic Execution" begin
        @test begin
            # Simple halt program
            instructions = UInt8[
                0x32,  # jump_ind
                0x00,  # register 0 (contains 0xFFFF0000 = halt address)
                0xFF, 0xFF, 0xFF, 0xFF
            ]
            opcode_mask = BitVector([1, 0, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.HALT
        end

        @test begin
            # Trap instruction
            instructions = UInt8[0x00]  # trap
            opcode_mask = BitVector([1])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.PANIC
        end
    end

    @testset "Arithmetic Instructions" begin
        @test begin
            # ADD32: 42 + 58 = 100
            instructions = UInt8[
                0x33, 0x00, 42, 0, 0, 0,  # load_imm r0, 42
                0x33, 0x10, 58, 0, 0, 0,  # load_imm r1, 58
                0xBE, 0x10, 0x20,          # add_32 r2 = r0 + r1
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1, 0, 0,
                1, 0, 0, 0, 0, 0
            ])

            program = create_program(instructions, opcode_mask)
            state = SecurePVM.PVMState(
                UInt32(0), Int64(1000), zeros(UInt64, 13),
                SecurePVM.IsolatedMemory(),
                instructions, opcode_mask, UInt32[],
                SecurePVM.CONTINUE, UInt32(0), UInt32(0), UInt64(0),
                Dict{UInt32, UInt32}(), Dict{UInt32, SecurePVM.CacheEntry}(),
                Tuple{UInt32, UInt32}[]
            )

            # Execute manually to check register values
            SecurePVM.interpret!(state, 10)

            state.registers[3] == 100  # r2 should contain 100
        end

        @test begin
            # ADD64: Large number addition
            a = UInt64(1) << 40
            b = UInt64(1) << 41

            instructions = UInt8[
                0x33, 0x00, # load_imm r0
                UInt8(a & 0xFF), UInt8((a >> 8) & 0xFF),
                UInt8((a >> 16) & 0xFF), UInt8((a >> 24) & 0xFF),
                0x33, 0x10, # load_imm r1
                UInt8(b & 0xFF), UInt8((b >> 8) & 0xFF),
                UInt8((b >> 16) & 0xFF), UInt8((b >> 24) & 0xFF),
                0xC8, 0x10, 0x20,  # add_64 r2 = r0 + r1
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1, 0, 0,
                1, 0, 0, 0, 0, 0
            ])

            program = create_program(instructions, opcode_mask)
            state = SecurePVM.PVMState(
                UInt32(0), Int64(1000), zeros(UInt64, 13),
                SecurePVM.IsolatedMemory(),
                instructions, opcode_mask, UInt32[],
                SecurePVM.CONTINUE, UInt32(0), UInt32(0), UInt64(0),
                Dict{UInt32, UInt32}(), Dict{UInt32, SecurePVM.CacheEntry}(),
                Tuple{UInt32, UInt32}[]
            )

            SecurePVM.interpret!(state, 10)

            state.registers[3] == a + b
        end
    end

    @testset "Memory Safety" begin
        @test begin
            # Forbidden zone access (should panic)
            instructions = UInt8[
                0x34, 0x00, 0x10, 0x00, 0x00, 0x00  # load_u8 r0, [0x0010] (in forbidden zone)
            ]
            opcode_mask = BitVector([1, 0, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.PANIC
        end

        @test begin
            # Valid memory access
            test_addr = UInt32(0x100000)  # Well above forbidden zone

            instructions = UInt8[
                0x33, 0x00, 42, 0, 0, 0,  # load_imm r0, 42
                0x3B, 0x00,  # store_u8 [addr], r0
                UInt8(test_addr & 0xFF), UInt8((test_addr >> 8) & 0xFF),
                UInt8((test_addr >> 16) & 0xFF), UInt8((test_addr >> 24) & 0xFF),
                0x34, 0x10,  # load_u8 r1, [addr]
                UInt8(test_addr & 0xFF), UInt8((test_addr >> 8) & 0xFF),
                UInt8((test_addr >> 16) & 0xFF), UInt8((test_addr >> 24) & 0xFF),
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0
            ])

            program = create_program(instructions, opcode_mask)
            state = SecurePVM.PVMState(
                UInt32(0), Int64(1000), zeros(UInt64, 13),
                SecurePVM.IsolatedMemory(),
                instructions, opcode_mask, UInt32[],
                SecurePVM.CONTINUE, UInt32(0), UInt32(0), UInt64(0),
                Dict{UInt32, UInt32}(), Dict{UInt32, SecurePVM.CacheEntry}(),
                Tuple{UInt32, UInt32}[]
            )

            # Need to allocate and set permissions for the page
            page_idx = test_addr >> 12
            page = SecurePVM.SecurePage()
            page.perm = SecurePVM.PERM_READ | SecurePVM.PERM_WRITE
            state.memory.pages[page_idx] = page

            SecurePVM.interpret!(state, 20)

            state.registers[2] == 42  # r1 should contain the value we stored
        end
    end

    @testset "Jump Instructions" begin
        @test begin
            # Direct jump
            instructions = UInt8[
                0x28, 0x03, 0x00, 0x00, 0x00,  # jump +3
                0x00,  # trap (should be skipped)
                0x00,  # trap (should be skipped)
                0x01,  # fallthrough (target)
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.HALT  # Should halt, not panic
        end

        @test begin
            # Jump table test
            jump_target = UInt32(8)
            instructions = UInt8[
                0x33, 0x00, 0x02, 0x00, 0x00, 0x00,  # load_imm r0, 2 (DYNAM_ALIGN)
                0x32, 0x00, 0x00, 0x00, 0x00, 0x00,  # jump_ind r0 (use jump table[0])
                0x00,  # trap (should be skipped)
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF   # halt (jump target at offset 8)
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1,
                1, 0, 0, 0, 0, 0
            ])
            jump_table = [jump_target]

            program = create_program(instructions, opcode_mask, jump_table)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.HALT
        end
    end

    @testset "Gas Metering" begin
        @test begin
            # Out of gas
            instructions = UInt8[
                0x01,  # fallthrough
                0x01,  # fallthrough
                0x01,  # fallthrough
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([1, 1, 1, 1, 0, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], 2)  # Only 2 gas

            status == SecurePVM.OOG
        end
    end

    @testset "Register Operations" begin
        @test begin
            # Move register
            instructions = UInt8[
                0x33, 0x00, 0x2A, 0x00, 0x00, 0x00,  # load_imm r0, 42
                0x64, 0x10,  # move_reg r1 = r0
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0,
                1, 0, 0, 0, 0, 0
            ])

            program = create_program(instructions, opcode_mask)
            state = SecurePVM.PVMState(
                UInt32(0), Int64(1000), zeros(UInt64, 13),
                SecurePVM.IsolatedMemory(),
                instructions, opcode_mask, UInt32[],
                SecurePVM.CONTINUE, UInt32(0), UInt32(0), UInt64(0),
                Dict{UInt32, UInt32}(), Dict{UInt32, SecurePVM.CacheEntry}(),
                Tuple{UInt32, UInt32}[]
            )

            SecurePVM.interpret!(state, 10)

            state.registers[1] == 42 && state.registers[2] == 42  # Both should have 42
        end
    end

    @testset "Host Calls" begin
        @test begin
            # ECALLI instruction
            host_id = UInt32(0x1234)
            instructions = UInt8[
                0x0A,  # ecalli
                UInt8(host_id & 0xFF), UInt8((host_id >> 8) & 0xFF), 0x00, 0x00
            ]
            opcode_mask = BitVector([1, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.HOST
        end
    end

    @testset "Edge Cases" begin
        @test begin
            # Empty program
            program = create_program(UInt8[], BitVector([]))
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.PANIC
        end

        @test begin
            # Invalid opcode mask (no opcode bit set)
            instructions = UInt8[0x01, 0x01]
            opcode_mask = BitVector([0, 0])  # No valid opcodes

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.PANIC
        end

        @test begin
            # PC overflow
            instructions = UInt8[
                0x28, 0xFF, 0xFF, 0xFF, 0x7F  # jump to huge offset
            ]
            opcode_mask = BitVector([1, 0, 0, 0, 0])

            program = create_program(instructions, opcode_mask)
            status, output, gas_used = SecurePVM.execute(program, UInt8[], UInt64(1000))

            status == SecurePVM.PANIC
        end
    end

    @testset "Performance & JIT Preparation" begin
        @test begin
            # Hot path detection
            instructions = UInt8[
                0x33, 0x00, 0x0A, 0x00, 0x00, 0x00,  # load_imm r0, 10
                0x33, 0x10, 0x01, 0x00, 0x00, 0x00,  # load_imm r1, 1
                # Loop start (offset 12)
                0xBF, 0x00, 0x10,  # sub_32 r1 = r0 - r1
                0x28, 0xF7, 0xFF, 0xFF, 0xFF,  # jump -9 (back to loop start) if not zero
                0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF  # halt
            ]
            opcode_mask = BitVector([
                1, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0,
                1, 0, 0,
                1, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0
            ])

            program = create_program(instructions, opcode_mask)
            state = SecurePVM.PVMState(
                UInt32(0), Int64(1000), zeros(UInt64, 13),
                SecurePVM.IsolatedMemory(),
                instructions, opcode_mask, UInt32[],
                SecurePVM.CONTINUE, UInt32(0), UInt32(0), UInt64(0),
                Dict{UInt32, UInt32}(), Dict{UInt32, SecurePVM.CacheEntry}(),
                Tuple{UInt32, UInt32}[]
            )

            # Execute with profiling
            SecurePVM.interpret!(state, 100)

            # Check that loop instructions were marked as hot
            haskey(state.hot_paths, UInt32(12)) && state.hot_paths[UInt32(12)] > 1
        end
    end
end

# Run tests
println("Running PVM interpreter tests...")
@time @testset "All PVM Tests" begin
    include("test_pvm.jl")
end