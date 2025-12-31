# Doom Demo - Continuous frame rendering from PVM execution
#
# Usage:
#   julia --project=. src/testnet/doom_demo.jl
#
# This runs Doom in the PVM and saves frames to /tmp/doom_frames/
# With video=true, streams to /tmp/doom_live.mp4 in realtime

const SRC_DIR = dirname(@__DIR__)

# Include dependencies
include(joinpath(SRC_DIR, "crypto", "Blake2b.jl"))
include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))
include(joinpath(SRC_DIR, "pvm", "corevm_extension.jl"))

using .PVM
using .PolkaVMBlob
using .CoreVMExtension

function blake2b_256(data::Vector{UInt8})::Vector{UInt8}
    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, data, length(data))
    return output
end

function run_doom_demo(;max_frames=100, frames_dir="/tmp/doom_frames")
    # Find doom.corevm
    doom_paths = [
        "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm",
        "/tmp/polkajam-nightly-2025-12-15-linux-x86_64/doom.corevm",
        joinpath(SRC_DIR, "..", "doom.corevm"),
    ]

    doom_path = nothing
    for p in doom_paths
        if isfile(p)
            doom_path = p
            break
        end
    end

    if doom_path === nothing
        error("doom.corevm not found! Tried: $(doom_paths)")
    end

    println("Loading doom.corevm from: $doom_path")
    doom_data = read(doom_path)
    println("  Size: $(length(doom_data)) bytes")

    # Find PVM magic header "PVM\0" in the corevm file
    pvm_magic = findfirst(b"PVM\0", doom_data)
    if pvm_magic === nothing
        error("No PVM magic header found in corevm file")
    end

    # Extract PVM blob from magic header onwards
    pvm_blob = doom_data[pvm_magic[1]:end]
    println("  PVM blob: $(length(pvm_blob)) bytes (found at offset $(pvm_magic[1]))")

    # Parse PVM blob
    println("\nParsing PVM blob...")
    parsed = PolkaVMBlob.parse_polkavm_blob(pvm_blob)
    println("  Code: $(length(parsed.code)) bytes")
    println("  RO data: $(length(parsed.ro_data)) bytes")
    println("  RW data: $(length(parsed.rw_data)) bytes")

    # Create output directory
    mkpath(frames_dir)
    println("\nSaving frames to: $frames_dir")

    # Memory layout constants (matching testnet exactly)
    VM_MAX_PAGE_SIZE = UInt32(0x10000)
    align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)

    ro_data_address_space = align_64k(parsed.ro_data_size)
    RO_BASE = UInt32(0x10000)
    RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
    STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
    STACK_LOW = UInt32(STACK_HIGH - parsed.stack_size)
    HEAP_BASE = UInt32(RW_BASE + parsed.rw_data_size)

    println("  Stack size: $(parsed.stack_size) bytes")
    println("  RO_BASE: 0x$(string(RO_BASE, base=16))")
    println("  RW_BASE: 0x$(string(RW_BASE, base=16))")
    println("  STACK_LOW: 0x$(string(STACK_LOW, base=16))")
    println("  STACK_HIGH: 0x$(string(STACK_HIGH, base=16))")
    println("  HEAP_BASE: 0x$(string(HEAP_BASE, base=16))")

    # Expand RW data to full size
    rw_data_full = zeros(UInt8, parsed.rw_data_size)
    copyto!(rw_data_full, 1, parsed.rw_data, 1, length(parsed.rw_data))

    # Initialize memory using the same approach as testnet
    memory = PVM.Memory()
    PVM.init_memory_regions!(memory,
        RO_BASE, UInt32(length(parsed.ro_data)), parsed.ro_data,
        RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
        STACK_LOW, STACK_HIGH,
        HEAP_BASE, STACK_LOW)

    # Get opcode mask and skip distances
    opcode_mask = PolkaVMBlob.get_opcode_mask(parsed)
    skip_distances = PVM.precompute_skip_distances(opcode_mask)

    # Initialize registers
    regs = zeros(UInt64, 13)
    regs[1] = UInt64(0xFFFF0000)  # a0 = special marker
    regs[2] = UInt64(STACK_HIGH)  # a1 = stack top

    # Create PVM state using PVMState constructor
    initial_gas = Int64(100_000_000_000)  # 100 billion gas
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, initial_gas,
        parsed.code, opcode_mask, skip_distances, regs, memory, parsed.jump_table,
        UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

    # Framebuffer dimensions
    WIDTH = 320
    HEIGHT = 200

    # Set up CoreVM extension
    corevm = CoreVMExtension.CoreVMHostCalls(width=WIDTH, height=HEIGHT)
    CoreVMExtension.set_heap_base!(corevm, HEAP_BASE)

    # Frame capture state
    frame_count = Ref(0)
    total_steps = Ref(0)
    start_time = time()
    last_frame_time = Ref(start_time)

    # Pre-allocate buffers
    rgb_frame = Vector{UInt8}(undef, WIDTH * HEIGHT * 3)
    palette_buf = Vector{UInt8}(undef, 768)
    pixels_buf = Vector{UInt8}(undef, WIDTH * HEIGHT)

    fb_callback = function(pvm_state, fb_addr, fb_size)
        if fb_size >= 64769  # 1 + 768 + 64000
            # Bulk read palette (768 bytes at fb_addr+1)
            PVM.read_bytes!(pvm_state, UInt32(fb_addr + 1), palette_buf, 768)

            # Bulk read indexed pixels (64000 bytes at fb_addr+769)
            PVM.read_bytes!(pvm_state, UInt32(fb_addr + 769), pixels_buf, WIDTH * HEIGHT)

            # Convert indexed to RGB using palette
            @inbounds for i in 1:WIDTH*HEIGHT
                idx = pixels_buf[i]
                base = Int(idx) * 3
                rgb_frame[(i-1)*3 + 1] = palette_buf[base + 1]
                rgb_frame[(i-1)*3 + 2] = palette_buf[base + 2]
                rgb_frame[(i-1)*3 + 3] = palette_buf[base + 3]
            end

            frame_count[] += 1

            # Calculate FPS
            now = time()
            elapsed = now - start_time
            frame_elapsed = now - last_frame_time[]
            last_frame_time[] = now
            fps = frame_count[] / elapsed
            instant_fps = 1.0 / max(frame_elapsed, 0.001)

            # Save frame
            frame_path = joinpath(frames_dir, "frame_$(lpad(frame_count[], 5, '0')).rgb")
            open(frame_path, "w") do f
                write(f, rgb_frame)
            end

            # Also save as latest.rgb for easy viewing
            latest_path = joinpath(frames_dir, "latest.rgb")
            open(latest_path, "w") do f
                write(f, rgb_frame)
            end

            # Convert to PNG if ffmpeg available
            png_path = joinpath(frames_dir, "latest.png")
            try
                run(pipeline(`ffmpeg -y -f rawvideo -pixel_format rgb24 -video_size 320x200 -i $latest_path $png_path`, stderr=devnull))
            catch
                # ffmpeg not available, skip PNG conversion
            end

            # Print status
            mips = total_steps[] / elapsed / 1_000_000
            print("\r\033[K")  # Clear line
            print("Frame $(frame_count[]): $(round(fps, digits=1)) avg FPS, $(round(instant_fps, digits=1)) instant FPS, $(round(mips, digits=1)) MIPS, $(round(elapsed, digits=1))s elapsed")
            flush(stdout)

            if frame_count[] >= max_frames
                println("\n\nReached max frames ($max_frames)")
            end
        end
    end

    CoreVMExtension.set_framebuffer_callback!(corevm, fb_callback)

    println("\nStarting Doom execution...")
    println("Press Ctrl+C to stop\n")

    # Main execution loop
    try
        while state.status == PVM.CONTINUE && state.gas > 0 && frame_count[] < max_frames
            PVM.step!(state)
            total_steps[] += 1

            if state.status == PVM.HOST
                handled = CoreVMExtension.handle_corevm_host_call!(state, corevm)
                if handled
                    skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                    state.pc = state.pc + 1 + skip
                else
                    println("\nUnhandled host call: $(state.host_call_id)")
                    break
                end
            end
        end
    catch e
        if e isa InterruptException
            println("\n\nInterrupted by user")
        else
            rethrow(e)
        end
    end

    # Final stats
    elapsed = time() - start_time
    println("\n")
    println("=== Final Stats ===")
    println("Total frames: $(frame_count[])")
    println("Total steps: $(total_steps[])")
    println("Elapsed time: $(round(elapsed, digits=2))s")
    println("Average FPS: $(round(frame_count[] / elapsed, digits=2))")
    println("Average MIPS: $(round(total_steps[] / elapsed / 1_000_000, digits=2))")
    println("\nFrames saved to: $frames_dir")
    println("View latest frame: $frames_dir/latest.png")
end

# Run if executed directly
if abspath(PROGRAM_FILE) == @__FILE__
    run_doom_demo(max_frames=1000)
end
