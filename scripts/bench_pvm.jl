# Quick PVM benchmark - 50 frames of Doom

const SRC_DIR = joinpath(dirname(@__DIR__), "src")

include(joinpath(SRC_DIR, "crypto", "Blake2b.jl"))
include(joinpath(SRC_DIR, "pvm", "pvm.jl"))
include(joinpath(SRC_DIR, "pvm", "polkavm_blob.jl"))
include(joinpath(SRC_DIR, "pvm", "corevm_extension.jl"))

using .PVM
using .PolkaVMBlob
using .CoreVMExtension

function run_benchmark()
    # Load doom
    doom_path = "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm"
    doom_data = read(doom_path)
    pvm_magic = findfirst(b"PVM\0", doom_data)
    pvm_blob = doom_data[pvm_magic[1]:end]
    parsed = PolkaVMBlob.parse_polkavm_blob(pvm_blob)

    # Memory setup
    VM_MAX_PAGE_SIZE = UInt32(0x10000)
    align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
    ro_data_address_space = align_64k(parsed.ro_data_size)
    RO_BASE = UInt32(0x10000)
    RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
    STACK_HIGH = UInt32(0xFFFF0000 - VM_MAX_PAGE_SIZE)
    STACK_LOW = UInt32(STACK_HIGH - parsed.stack_size)
    HEAP_BASE = UInt32(RW_BASE + parsed.rw_data_size)

    rw_data_full = zeros(UInt8, parsed.rw_data_size)
    copyto!(rw_data_full, 1, parsed.rw_data, 1, length(parsed.rw_data))

    memory = PVM.Memory()
    PVM.init_memory_regions!(memory,
        RO_BASE, UInt32(length(parsed.ro_data)), parsed.ro_data,
        RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
        STACK_LOW, STACK_HIGH,
        HEAP_BASE, STACK_LOW)

    opcode_mask = PolkaVMBlob.get_opcode_mask(parsed)
    skip_distances = PVM.precompute_skip_distances(opcode_mask)

    regs = zeros(UInt64, 13)
    regs[1] = UInt64(0xFFFF0000)
    regs[2] = UInt64(STACK_HIGH)

    initial_gas = Int64(100_000_000_000)
    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, initial_gas,
        parsed.code, opcode_mask, skip_distances, regs, memory, parsed.jump_table,
        UInt32(0), Vector{Vector{UInt8}}(), Dict{UInt32, PVM.GuestPVM}())

    corevm = CoreVMExtension.CoreVMHostCalls(width=320, height=200)
    CoreVMExtension.set_heap_base!(corevm, HEAP_BASE)

    frame_count = Ref(0)
    total_steps = Ref(0)
    start_time = time()

    fb_callback = function(pvm_state, fb_addr, fb_size)
        frame_count[] += 1
    end

    CoreVMExtension.set_framebuffer_callback!(corevm, fb_callback)

    println("Running 50 frames benchmark...")
    while state.status == PVM.CONTINUE && state.gas > 0 && frame_count[] < 50
        PVM.step!(state)
        total_steps[] += 1

        if state.status == PVM.HOST
            handled = CoreVMExtension.handle_corevm_host_call!(state, corevm)
            if handled
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
            else
                break
            end
        end
    end

    elapsed = time() - start_time
    println("\n=== Final Stats ===")
    println("Total frames: $(frame_count[])")
    println("Total steps: $(total_steps[])")
    println("Elapsed time: $(round(elapsed, digits=2))s")
    println("Average FPS: $(round(frame_count[] / elapsed, digits=2))")
    println("Average MIPS: $(round(total_steps[] / elapsed / 1_000_000, digits=2))")
end

run_benchmark()
