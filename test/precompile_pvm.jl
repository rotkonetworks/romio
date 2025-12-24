# PVM precompilation workload for PackageCompiler
# exercises interpreter hot paths using benchmark-style execution

using JAM
using JAM: PVM, PolkaVMBlob, CoreVMExtension
using .PVM, .PolkaVMBlob, .CoreVMExtension

println("Precompiling PVM interpreter...")

# try to find doom.corevm for realistic workload
const DOOM_PATHS = [
    "/tmp/polkajam-nightly-2025-12-22-linux-x86_64/doom.corevm",
    "/tmp/polkajam-nightly-2025-12-15-linux-x86_64/doom.corevm",
    "/tmp/polkajam-v0.1.27-linux-x86_64/doom.corevm",
    expanduser("~/doom.corevm"),
]

function find_doom_corevm()
    for p in DOOM_PATHS
        if isfile(p)
            return p
        end
    end
    return nothing
end

function run_doom_workload(doom_path::String)
    println("  Found doom.corevm, using real workload...")

    WIDTH = 320
    HEIGHT = 200

    doom_data = read(doom_path)
    pvm_magic = UInt8[0x50, 0x56, 0x4d, 0x00]
    pvm_offset = 0
    for i in 1:length(doom_data)-3
        if doom_data[i:i+3] == pvm_magic
            pvm_offset = i
            break
        end
    end
    pvm_blob = doom_data[pvm_offset:end]

    prog = parse_polkavm_blob(pvm_blob)
    opcode_mask = get_opcode_mask(prog)

    VM_MAX_PAGE_SIZE = UInt32(0x10000)
    align_64k(x) = (x + VM_MAX_PAGE_SIZE - 1) & ~(VM_MAX_PAGE_SIZE - 1)
    ro_data_address_space = align_64k(prog.ro_data_size)

    RO_BASE = UInt32(0x10000)
    RW_BASE = UInt32(RO_BASE + ro_data_address_space + VM_MAX_PAGE_SIZE)
    STACK_TOP = UInt32(0xFFFF1000)
    STACK_START = UInt32(0xfffe0000)
    STACK_LOW = UInt32(0xfffd0000)
    PAGE_SIZE = UInt32(0x1000)
    align_4k(x) = (x + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    RW_SIZE_ALIGNED = align_4k(prog.rw_data_size)
    HEAP_BASE = UInt32(RW_BASE + prog.rw_data_size)

    corevm = CoreVMHostCalls(width=WIDTH, height=HEIGHT)
    set_heap_base!(corevm, HEAP_BASE)

    skip_distances = PVM.precompute_skip_distances(opcode_mask)

    rw_data_full = zeros(UInt8, RW_SIZE_ALIGNED)
    copyto!(rw_data_full, 1, prog.rw_data, 1, length(prog.rw_data))

    memory = PVM.Memory()
    PVM.init_memory_regions!(memory,
        RO_BASE, UInt32(length(prog.ro_data)), prog.ro_data,
        RW_BASE, UInt32(length(rw_data_full)), rw_data_full,
        STACK_LOW, STACK_TOP,
        HEAP_BASE, STACK_LOW
    )

    regs = zeros(UInt64, 13)
    regs[1] = UInt64(0xFFFF0000)
    regs[2] = UInt64(STACK_START)

    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(100_000_000_000),
        prog.code, opcode_mask, skip_distances, regs, memory,
        prog.jump_table, UInt32(0), Vector{Vector{UInt8}}(),
        Dict{UInt32, PVM.GuestPVM}()
    )

    # run warmup frames in a function for proper JIT
    frame_count = Ref(0)
    fb_callback = function(pvm_state, fb_addr, fb_size)
        frame_count[] += 1
    end
    set_framebuffer_callback!(corevm, fb_callback)

    function run_frames(state, corevm, n_frames)
        frame_start = frame_count[]
        while frame_count[] < frame_start + n_frames && state.gas > 0
            PVM.step!(state)
            if state.status == PVM.HOST
                handle_corevm_host_call!(state, corevm)
                skip = PVM.skip_distance(state.opcode_mask, Int(state.pc) + 1)
                state.pc = state.pc + 1 + skip
            elseif state.status != PVM.CONTINUE
                break
            end
        end
        return frame_count[] - frame_start
    end

    # run 10 frames to exercise all instruction paths
    frames = run_frames(state, corevm, 10)
    println("  Ran $frames warmup frames")

    # exercise bulk memory reads
    if frame_count[] > 0
        data = PVM.read_bytes_bulk(state, UInt64(HEAP_BASE), 256)
        println("  Bulk memory read: $(length(data)) bytes")
    end
end

function run_minimal_workload()
    println("  No doom.corevm found, using minimal workload...")

    # minimal workload - just exercise memory and state creation
    memory = PVM.Memory()
    ro_data = zeros(UInt8, 256)
    rw_data = zeros(UInt8, 4096)

    PVM.init_memory_regions!(memory,
        UInt32(0x10000), UInt32(256), ro_data,
        UInt32(0x20000), UInt32(4096), rw_data,
        UInt32(0xFFFF0000), UInt32(0xFFFF1000),
        UInt32(0x21000), UInt32(0xFFFF0000)
    )

    # simple trap program
    code = UInt8[0x00]  # trap
    opcode_mask = trues(1)
    skip_distances = PVM.precompute_skip_distances(opcode_mask)

    regs = zeros(UInt64, 13)
    regs[1] = UInt64(0xFFFF0000)
    regs[2] = UInt64(0x20000)

    state = PVM.PVMState(
        UInt32(0), PVM.CONTINUE, Int64(10000),
        code, opcode_mask, skip_distances, regs, memory,
        UInt32[], UInt32(0), Vector{Vector{UInt8}}(),
        Dict{UInt32, PVM.GuestPVM}()
    )

    PVM.step!(state)
    println("  Minimal workload complete, status=$(state.status)")
end

# main execution
doom_path = find_doom_corevm()
if doom_path !== nothing
    run_doom_workload(doom_path)
else
    run_minimal_workload()
end

println("PVM precompilation complete")
