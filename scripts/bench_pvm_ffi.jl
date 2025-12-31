# Quick PVM FFI benchmark - 50 frames of Doom using Rust polkavm JIT

const SRC_DIR = joinpath(dirname(@__DIR__), "src")

include(joinpath(SRC_DIR, "pvm", "polkavm_ffi.jl"))
using .PolkaVMFFI

function run_benchmark()
    # Load doom
    doom_path = "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm"
    doom_data = read(doom_path)

    # Find PVM magic
    pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
    pvm_offset = 0
    for i in 1:length(doom_data)-3
        if doom_data[i:i+3] == pvm_magic
            pvm_offset = i
            break
        end
    end

    if pvm_offset == 0
        error("No PVM magic found")
    end

    pvm_blob = doom_data[pvm_offset:end]
    println("Creating Rust polkavm instance...")

    # Create VM
    vm = PolkaVMFFI.create_pvm(pvm_blob)

    frame_count = Ref(0)
    start_time = time()

    # Host call IDs
    HOST_CALL_FB = UInt32(100)  # Framebuffer commit
    HOST_CALL_SBRK = UInt32(1)  # Memory allocation

    println("Running 50 frames benchmark with Rust polkavm FFI (JIT)...")

    while frame_count[] < 50
        # Run some steps
        result = PolkaVMFFI.run_steps!(vm, 10_000_000)

        if result.status == :host
            state = PolkaVMFFI.get_state(vm)
            host_call_id = state.host_call_id

            if host_call_id == HOST_CALL_FB
                frame_count[] += 1
                # Resume execution
                PolkaVMFFI.set_reg!(vm, 0, UInt64(0))  # Return success
            elseif host_call_id == HOST_CALL_SBRK
                # Handle sbrk
                amount = state.regs[1]
                # For simplicity, just return success
                PolkaVMFFI.set_reg!(vm, 0, UInt64(0))
            else
                # Unknown host call, skip
                PolkaVMFFI.set_reg!(vm, 0, UInt64(0))
            end
        elseif result.status == :halt || result.status == :panic
            println("Execution ended: $(result.status)")
            break
        end
    end

    elapsed = time() - start_time
    println("\n=== Rust FFI Stats ===")
    println("Total frames: $(frame_count[])")
    println("Elapsed time: $(round(elapsed, digits=2))s")
    println("Average FPS: $(round(frame_count[] / elapsed, digits=2))")

    PolkaVMFFI.destroy_pvm!(vm)
end

run_benchmark()
