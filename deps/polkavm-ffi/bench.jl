# PVM benchmark script
include("../../src/pvm/polkavm_ffi.jl")
using .PolkaVMFFI

println("Creating engine...")
engine = PvmEngine()
println("Engine created successfully")

# Load doom
doom_path = "/tmp/polkajam-nightly-2025-12-15-linux-x86_64/doom.corevm"
doom_data = read(doom_path)

# Find PVM magic
pvm_magic = UInt8[0x50, 0x56, 0x4d]
pvm_offset = 1
for i in 1:length(doom_data)-2
    if doom_data[i:i+2] == pvm_magic
        global pvm_offset = i
        break
    end
end
pvm_blob = doom_data[pvm_offset:end]
println("PVM blob found at offset $(pvm_offset): $(length(pvm_blob)) bytes")

println("Loading module...")
mod = PvmModule(engine, pvm_blob)
mem = memory_info(mod)
inst = PvmInstance(engine, mod)

# Setup
set_reg!(inst, REG_SP, UInt64(mem.stack_address_high))
entry_pc = export_pc(mod, 0)
prepare_call!(inst, entry_pc)

# Benchmark: run for 100 frames
println("Running benchmark (100 frames)...")
set_gas!(inst, 5_000_000_000)  # 5B gas - plenty
start = time()

frame_count = 0
while true
    result = run!(inst)
    if result.status == HOST
        if result.host_call == 0
            set_reg!(inst, REG_A0, UInt64(320))
            set_reg!(inst, REG_A1, UInt64(200))
        elseif result.host_call == 1
            pages = get_reg(inst, REG_A0)
            new_ptr = sbrk!(inst, UInt32(pages))
            set_reg!(inst, REG_A0, UInt64(new_ptr))
        elseif result.host_call == 2
            global frame_count += 1
            if frame_count >= 100
                break
            end
        end
    elseif result.status == OOG
        println("Out of gas after $frame_count frames")
        break
    else
        println("Stopped: $(result.status)")
        break
    end
end

elapsed = time() - start
fps = frame_count / elapsed
println("Rendered $frame_count frames in $(round(elapsed, digits=2))s = $(round(fps, digits=1)) FPS")
