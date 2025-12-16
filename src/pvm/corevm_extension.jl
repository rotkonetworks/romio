# CoreVM Host Call Extension for PVM
# Implements the CoreVM-specific host calls used by applications like Doom

module CoreVMExtension

using ..PVM: PVMState, CONTINUE, HOST, Memory

# CoreVM host call IDs
const COREVM_INIT = 0       # Initialize (returns screen size)
const COREVM_SBRK = 1       # Memory allocation (sbrk)
const COREVM_FRAMEBUFFER = 2 # Submit framebuffer

"""
    CoreVMHostCalls

Extension for CoreVM-style host calls (used by Doom, etc.)
"""
mutable struct CoreVMHostCalls
    # Screen dimensions
    width::UInt32
    height::UInt32

    # Heap management
    heap_base::UInt32
    heap_ptr::UInt32

    # Framebuffer callback: (state, fb_addr, fb_size) -> nothing
    framebuffer_callback::Union{Function, Nothing}
end

"""
    CoreVMHostCalls(; width=320, height=200, heap_base=0x100000)

Create a CoreVM host call extension with default Doom screen size.
"""
function CoreVMHostCalls(; width=320, height=200, heap_base=UInt32(0x100000))
    CoreVMHostCalls(
        UInt32(width),
        UInt32(height),
        UInt32(heap_base),
        UInt32(heap_base),
        nothing
    )
end

"""
    set_framebuffer_callback!(ext::CoreVMHostCalls, callback)

Set the framebuffer callback function.
Callback signature: (state, fb_addr::UInt32, fb_size::UInt32) -> nothing
"""
function set_framebuffer_callback!(ext::CoreVMHostCalls, callback::Function)
    ext.framebuffer_callback = callback
end

"""
    set_heap_base!(ext::CoreVMHostCalls, base::UInt32)

Set the heap base address after memory setup.
"""
function set_heap_base!(ext::CoreVMHostCalls, base::UInt32)
    ext.heap_base = base
    ext.heap_ptr = base
end

"""
    handle_corevm_host_call!(state::PVMState, ext::CoreVMHostCalls) -> Bool

Handle a CoreVM host call. Returns true if handled.
"""
function handle_corevm_host_call!(state::PVMState, ext::CoreVMHostCalls)
    call_id = Int(state.host_call_id)

    if call_id == COREVM_INIT
        # INIT: Return screen dimensions
        # ω7 (reg 8) = width, ω8 (reg 9) = height
        state.registers[8] = UInt64(ext.width)
        state.registers[9] = UInt64(ext.height)
        state.gas -= 10
        state.status = CONTINUE
        return true

    elseif call_id == COREVM_SBRK
        # SBRK: Allocate heap pages
        # Input: ω7 = pages to allocate
        # Output: ω7 = pointer to allocated memory
        pages = UInt32(state.registers[8])
        old_ptr = ext.heap_ptr
        ext.heap_ptr += pages * 4096
        state.registers[8] = UInt64(old_ptr)
        state.gas -= 10
        state.status = CONTINUE
        return true

    elseif call_id == COREVM_FRAMEBUFFER
        # FRAMEBUFFER: Submit frame for display
        # Input: ω7 = framebuffer address, ω8 = size
        fb_addr = UInt32(state.registers[8])
        fb_size = UInt32(state.registers[9])

        # Call the callback if registered
        if ext.framebuffer_callback !== nothing
            ext.framebuffer_callback(state, fb_addr, fb_size)
        end

        state.gas -= 100
        state.status = CONTINUE
        return true
    end

    return false  # Not a CoreVM host call
end

export CoreVMHostCalls, set_framebuffer_callback!, set_heap_base!, handle_corevm_host_call!

end # module
