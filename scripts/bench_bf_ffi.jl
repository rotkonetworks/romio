# Benchmark: Native BF vs BLC-based BF interpreter using Rust PolkaVM FFI
#
# Compares execution time and gas usage for:
# - 0xBF prefix: Native C brainfuck interpreter
# - 0xB0 prefix: John Tromp's BLC-encoded BF interpreter

const SRC_DIR = joinpath(dirname(@__DIR__), "src")

include(joinpath(SRC_DIR, "pvm", "polkavm_ffi.jl"))

using .PolkaVMFFI

# BF program: output 'A' (65)
# ++++++++[>++++++++<-]>+.  = 64 + 1 = 65 = 'A'
const BF_A = collect(UInt8, "++++++++[>++++++++<-]>+.")

function load_blc_vm()
    blc_path = "/home/alice/rotko/blc-service/services/output/blc-vm.corevm"
    blc_data = read(blc_path)

    # Find PVM magic
    pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
    pvm_offset = 0
    for i in 1:length(blc_data)-3
        if blc_data[i:i+3] == pvm_magic
            pvm_offset = i
            break
        end
    end

    if pvm_offset == 0
        error("No PVM magic found")
    end

    return blc_data[pvm_offset:end]
end

function run_bf_test(pvm_blob::Vector{UInt8}, mode::Symbol)
    bf_program = copy(BF_A)

    # Prepare payload based on mode
    if mode == :native
        payload = UInt8[0xBF]
        append!(payload, bf_program)
    elseif mode == :blc
        payload = UInt8[0xB0]
        append!(payload, bf_program)
    else
        error("Unknown mode: $mode")
    end

    println("  Payload: $(length(payload)) bytes, prefix=0x$(string(payload[1], base=16))")

    # Create engine and module (use interpreter mode to avoid JIT issues)
    engine = PvmEngine(interpreter=true)
    mod = PvmModule(engine, pvm_blob)
    inst = PvmInstance(engine, mod)

    # Find jb_refine entry point
    entry_pc = UInt32(0)
    for i in 0:exports_count(mod)-1
        name = export_name(mod, i)
        if name == "jb_refine"
            entry_pc = export_pc(mod, i)
            break
        end
    end

    if entry_pc == 0
        error("Could not find jb_refine export")
    end
    println("  jb_refine entry PC: $entry_pc")

    # Setup initial gas
    initial_gas = Int64(100_000_000)
    set_gas!(inst, initial_gas)

    # Prepare to call jb_refine
    prepare_call!(inst, entry_pc)

    output_data = UInt8[]
    max_iterations = 1000
    iterations = 0

    while iterations < max_iterations
        iterations += 1
        result = run!(inst)

        if result.status == HOST
            host_call_id = result.host_call

            if host_call_id == 1  # host_fetch
                # Get registers: a0=buf, a1=offset, a2=len, a3=discriminator
                buf_ptr = UInt32(get_reg(inst, REG_A0))
                offset = get_reg(inst, REG_A1)
                buf_len = get_reg(inst, REG_A2)
                discriminator = get_reg(inst, REG_A3)

                if discriminator == 13  # FETCH_PAYLOAD
                    # Write payload to buffer
                    write_len = min(length(payload), Int(buf_len))
                    if write_len > 0
                        write_memory!(inst, buf_ptr, payload[1:write_len])
                    end
                    # Return length written
                    set_reg!(inst, REG_A0, UInt64(write_len))
                else
                    # Unknown discriminator, return HOST_NONE
                    set_reg!(inst, REG_A0, UInt64(0xFFFFFFFFFFFFFFFF))
                end

            elseif host_call_id == 7  # host_export
                # Get registers: a0=ptr, a1=len
                ptr = UInt32(get_reg(inst, REG_A0))
                len = Int(get_reg(inst, REG_A1))

                if len > 0
                    data = read_memory(inst, ptr, UInt32(len))
                    if data !== nothing
                        append!(output_data, data)
                    end
                end
                # Return success
                set_reg!(inst, REG_A0, UInt64(0))

            else
                # Unknown host call - just return success
                set_reg!(inst, REG_A0, UInt64(0))
            end

        elseif result.status == HALT
            break
        elseif result.status == PANIC
            println("  PANIC!")
            break
        elseif result.status == OOG
            println("  Out of gas!")
            break
        end
    end

    gas_used = initial_gas - get_gas(inst)

    return (
        gas_used = gas_used,
        output = output_data
    )
end

function main()
    println("Loading blc-vm...")
    pvm_blob = load_blc_vm()
    println("  PVM blob size: $(length(pvm_blob)) bytes")

    println("\n=== Benchmark: Native BF (0xBF) vs BLC-based BF (0xB0) ===\n")

    println("BF program: $(String(copy(BF_A)))")
    println("Expected output: 'A' (0x41)\n")

    println("Running native BF (0xBF prefix)...")
    result_native = run_bf_test(pvm_blob, :native)
    println("  Gas used: $(result_native.gas_used)")
    native_output = String(copy(result_native.output))
    println("  Output: $(result_native.output) = '$native_output'")

    println("\nRunning BLC-based BF (0xB0 prefix)...")
    result_blc = run_bf_test(pvm_blob, :blc)
    println("  Gas used: $(result_blc.gas_used)")
    blc_output = String(copy(result_blc.output))
    println("  Output: $(result_blc.output) = '$blc_output'")

    if result_native.gas_used > 0 && result_blc.gas_used > 0
        println("\n=== Comparison ===")
        ratio = result_blc.gas_used / result_native.gas_used
        println("Gas ratio: $(round(ratio, digits=1))x")
        println("Native BF uses $(result_native.gas_used) gas")
        println("BLC-based BF uses $(result_blc.gas_used) gas")
    end
end

main()
