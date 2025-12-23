# PolkaVM FFI wrapper for Julia
# Provides access to the native PolkaVM implementation via FFI

module PolkaVMFFI

using Libdl

# Find and load the shared library
const LIBPOLKAVM = let
    # Look for the library in deps/polkavm-ffi/target/release
    lib_path = joinpath(@__DIR__, "..", "..", "deps", "polkavm-ffi", "target", "release")
    lib_name = Sys.iswindows() ? "polkavm_ffi.dll" :
               Sys.isapple() ? "libpolkavm_ffi.dylib" : "libpolkavm_ffi.so"
    full_path = joinpath(lib_path, lib_name)

    if !isfile(full_path)
        error("PolkaVM FFI library not found at $full_path. Run `cargo build --release` in deps/polkavm-ffi/")
    end

    dlopen(full_path)
end

# Result struct returned by pvm_instance_run
struct PvmResult
    status::UInt32      # 0=HALT, 1=PANIC, 2=OOG, 3=FAULT, 4=HOST
    gas_remaining::Int64
    host_call::UInt32
end

# Memory info struct
struct PvmMemoryInfo
    ro_data_address::UInt32
    ro_data_size::UInt32
    rw_data_address::UInt32
    rw_data_size::UInt32
    stack_address_low::UInt32
    stack_address_high::UInt32
    heap_base::UInt32
end

# Status codes
const HALT = UInt32(0)
const PANIC = UInt32(1)
const OOG = UInt32(2)
const FAULT = UInt32(3)
const HOST = UInt32(4)
const STEP = UInt32(5)

# Opaque handle types
const PvmEnginePtr = Ptr{Cvoid}
const PvmModulePtr = Ptr{Cvoid}
const PvmInstancePtr = Ptr{Cvoid}

# FFI function wrappers

"""Create a new PolkaVM engine with default configuration"""
function engine_new()::PvmEnginePtr
    ccall(dlsym(LIBPOLKAVM, :pvm_engine_new), PvmEnginePtr, ())
end

"""Create a new PolkaVM engine with interpreter backend"""
function engine_new_interpreter()::PvmEnginePtr
    ccall(dlsym(LIBPOLKAVM, :pvm_engine_new_interpreter), PvmEnginePtr, ())
end

"""Free a PolkaVM engine"""
function engine_free(engine::PvmEnginePtr)
    ccall(dlsym(LIBPOLKAVM, :pvm_engine_free), Cvoid, (PvmEnginePtr,), engine)
end

"""Load a module from a blob"""
function module_new(engine::PvmEnginePtr, blob::Vector{UInt8})::PvmModulePtr
    ccall(dlsym(LIBPOLKAVM, :pvm_module_new), PvmModulePtr,
          (PvmEnginePtr, Ptr{UInt8}, Csize_t),
          engine, blob, length(blob))
end

"""Load a module with step tracing enabled (for debugging)"""
function module_new_step(engine::PvmEnginePtr, blob::Vector{UInt8})::PvmModulePtr
    ccall(dlsym(LIBPOLKAVM, :pvm_module_new_step), PvmModulePtr,
          (PvmEnginePtr, Ptr{UInt8}, Csize_t),
          engine, blob, length(blob))
end

"""Free a module"""
function module_free(mod::PvmModulePtr)
    ccall(dlsym(LIBPOLKAVM, :pvm_module_free), Cvoid, (PvmModulePtr,), mod)
end

"""Get module memory info"""
function module_memory_info(mod::PvmModulePtr)::PvmMemoryInfo
    ccall(dlsym(LIBPOLKAVM, :pvm_module_memory_info), PvmMemoryInfo, (PvmModulePtr,), mod)
end

"""Create an instance from a module"""
function instance_new(engine::PvmEnginePtr, mod::PvmModulePtr)::PvmInstancePtr
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_new), PvmInstancePtr,
          (PvmEnginePtr, PvmModulePtr), engine, mod)
end

"""Free an instance"""
function instance_free(instance::PvmInstancePtr)
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_free), Cvoid, (PvmInstancePtr,), instance)
end

"""Set gas for an instance"""
function instance_set_gas(instance::PvmInstancePtr, gas::Int64)
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_set_gas), Cvoid,
          (PvmInstancePtr, Int64), instance, gas)
end

"""Get remaining gas from an instance"""
function instance_get_gas(instance::PvmInstancePtr)::Int64
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_get_gas), Int64, (PvmInstancePtr,), instance)
end

"""Set a register value"""
function instance_set_reg(instance::PvmInstancePtr, reg::UInt32, value::UInt64)
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_set_reg), Cvoid,
          (PvmInstancePtr, UInt32, UInt64), instance, reg, value)
end

"""Get a register value"""
function instance_get_reg(instance::PvmInstancePtr, reg::UInt32)::UInt64
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_get_reg), UInt64,
          (PvmInstancePtr, UInt32), instance, reg)
end

"""Read memory from instance"""
function instance_read_memory(instance::PvmInstancePtr, address::UInt32, length::UInt32)::Union{Vector{UInt8}, Nothing}
    buffer = Vector{UInt8}(undef, length)
    result = ccall(dlsym(LIBPOLKAVM, :pvm_instance_read_memory), Int32,
                   (PvmInstancePtr, UInt32, Ptr{UInt8}, UInt32),
                   instance, address, buffer, length)
    result == 0 ? buffer : nothing
end

"""Write memory to instance"""
function instance_write_memory(instance::PvmInstancePtr, address::UInt32, data::Vector{UInt8})::Bool
    result = ccall(dlsym(LIBPOLKAVM, :pvm_instance_write_memory), Int32,
                   (PvmInstancePtr, UInt32, Ptr{UInt8}, UInt32),
                   instance, address, data, length(data))
    result == 0
end

"""Run the instance until completion or host call"""
function instance_run(instance::PvmInstancePtr)::PvmResult
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_run), PvmResult, (PvmInstancePtr,), instance)
end

"""Get program counter"""
function instance_get_pc(instance::PvmInstancePtr)::UInt32
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_get_pc), UInt32, (PvmInstancePtr,), instance)
end

"""Reset instance to initial state"""
function instance_reset(instance::PvmInstancePtr)
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_reset), Cvoid, (PvmInstancePtr,), instance)
end

"""Grow heap by specified number of pages"""
function instance_sbrk(instance::PvmInstancePtr, pages::UInt32)::UInt32
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_sbrk), UInt32,
          (PvmInstancePtr, UInt32), instance, pages)
end

"""Get the current heap size"""
function instance_heap_size(instance::PvmInstancePtr)::UInt32
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_heap_size), UInt32, (PvmInstancePtr,), instance)
end

"""Prepare a call to an exported function by program counter"""
function instance_prepare_call(instance::PvmInstancePtr, pc::UInt32)::Int32
    ccall(dlsym(LIBPOLKAVM, :pvm_instance_prepare_call), Int32,
          (PvmInstancePtr, UInt32), instance, pc)
end

"""Get the number of exports in a module"""
function module_exports_count(mod::PvmModulePtr)::UInt32
    ccall(dlsym(LIBPOLKAVM, :pvm_module_exports_count), UInt32, (PvmModulePtr,), mod)
end

"""Get export name by index"""
function module_export_name(mod::PvmModulePtr, index::UInt32)::Union{String, Nothing}
    buffer = Vector{UInt8}(undef, 256)
    len = ccall(dlsym(LIBPOLKAVM, :pvm_module_export_name), Int32,
                (PvmModulePtr, UInt32, Ptr{UInt8}, UInt32),
                mod, index, buffer, UInt32(256))
    len >= 0 ? String(buffer[1:len]) : nothing
end

"""Get export program counter by index"""
function module_export_pc(mod::PvmModulePtr, index::UInt32)::UInt32
    ccall(dlsym(LIBPOLKAVM, :pvm_module_export_pc), UInt32,
          (PvmModulePtr, UInt32), mod, index)
end

"""Read framebuffer and convert indexed color to RGB24 in one FFI call (optimized for Doom)"""
function instance_read_framebuffer_rgb24(instance::PvmInstancePtr, fb_addr::UInt32, fb_size::UInt32, rgb_buffer::Vector{UInt8})::Bool
    result = ccall(dlsym(LIBPOLKAVM, :pvm_instance_read_framebuffer_rgb24), Int32,
                   (PvmInstancePtr, UInt32, UInt32, Ptr{UInt8}, UInt32),
                   instance, fb_addr, fb_size, rgb_buffer, UInt32(length(rgb_buffer)))
    result == 0
end

# Register names (matching our PVM convention)
const REG_RA = UInt32(0)
const REG_SP = UInt32(1)
const REG_T0 = UInt32(2)
const REG_T1 = UInt32(3)
const REG_T2 = UInt32(4)
const REG_S0 = UInt32(5)
const REG_S1 = UInt32(6)
const REG_A0 = UInt32(7)
const REG_A1 = UInt32(8)
const REG_A2 = UInt32(9)
const REG_A3 = UInt32(10)
const REG_A4 = UInt32(11)
const REG_A5 = UInt32(12)

# High-level wrapper types

mutable struct PvmEngine
    ptr::PvmEnginePtr

    function PvmEngine(; interpreter::Bool=false)
        ptr = interpreter ? engine_new_interpreter() : engine_new()
        if ptr == C_NULL
            error("Failed to create PolkaVM engine")
        end
        engine = new(ptr)
        finalizer(e -> engine_free(e.ptr), engine)
        engine
    end
end

mutable struct PvmModule
    ptr::PvmModulePtr
    engine::PvmEngine  # Keep reference to prevent GC

    function PvmModule(engine::PvmEngine, blob::Vector{UInt8})
        ptr = module_new(engine.ptr, blob)
        if ptr == C_NULL
            error("Failed to load PolkaVM module from blob")
        end
        mod = new(ptr, engine)
        finalizer(m -> module_free(m.ptr), mod)
        mod
    end

    # Constructor with pre-created ptr (for step tracing modules)
    function PvmModule(ptr::PvmModulePtr, engine::PvmEngine)
        if ptr == C_NULL
            error("Failed to load PolkaVM module - null pointer")
        end
        mod = new(ptr, engine)
        finalizer(m -> module_free(m.ptr), mod)
        mod
    end
end

function memory_info(mod::PvmModule)::PvmMemoryInfo
    module_memory_info(mod.ptr)
end

function exports_count(mod::PvmModule)::UInt32
    module_exports_count(mod.ptr)
end

function export_name(mod::PvmModule, index::Integer)::Union{String, Nothing}
    module_export_name(mod.ptr, UInt32(index))
end

function export_pc(mod::PvmModule, index::Integer)::UInt32
    module_export_pc(mod.ptr, UInt32(index))
end

mutable struct PvmInstance
    ptr::PvmInstancePtr
    engine::PvmEngine  # Keep reference to prevent GC
    module_ref::PvmModule  # Keep reference to prevent GC

    function PvmInstance(engine::PvmEngine, mod::PvmModule)
        ptr = instance_new(engine.ptr, mod.ptr)
        if ptr == C_NULL
            error("Failed to create PolkaVM instance")
        end
        inst = new(ptr, engine, mod)
        finalizer(i -> instance_free(i.ptr), inst)
        inst
    end
end

# Instance methods
set_gas!(inst::PvmInstance, gas::Int64) = instance_set_gas(inst.ptr, gas)
get_gas(inst::PvmInstance) = instance_get_gas(inst.ptr)
set_reg!(inst::PvmInstance, reg::UInt32, value::UInt64) = instance_set_reg(inst.ptr, reg, value)
get_reg(inst::PvmInstance, reg::UInt32) = instance_get_reg(inst.ptr, reg)
read_memory(inst::PvmInstance, addr::UInt32, len::UInt32) = instance_read_memory(inst.ptr, addr, len)
write_memory!(inst::PvmInstance, addr::UInt32, data::Vector{UInt8}) = instance_write_memory(inst.ptr, addr, data)
run!(inst::PvmInstance) = instance_run(inst.ptr)
get_pc(inst::PvmInstance) = instance_get_pc(inst.ptr)
reset!(inst::PvmInstance) = instance_reset(inst.ptr)
sbrk!(inst::PvmInstance, pages::UInt32) = instance_sbrk(inst.ptr, pages)
heap_size(inst::PvmInstance) = instance_heap_size(inst.ptr)
prepare_call!(inst::PvmInstance, pc::UInt32) = instance_prepare_call(inst.ptr, pc)

"""Read Doom framebuffer and convert indexed to RGB24 in one optimized FFI call"""
read_framebuffer_rgb24!(inst::PvmInstance, fb_addr::UInt32, fb_size::UInt32, rgb_buffer::Vector{UInt8}) =
    instance_read_framebuffer_rgb24(inst.ptr, fb_addr, fb_size, rgb_buffer)

export PvmEngine, PvmModule, PvmInstance, PvmResult, PvmMemoryInfo
export HALT, PANIC, OOG, FAULT, HOST
export REG_RA, REG_SP, REG_T0, REG_T1, REG_T2, REG_S0, REG_S1
export REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_A5
export set_gas!, get_gas, set_reg!, get_reg, read_memory, write_memory!
export run!, get_pc, reset!, sbrk!, heap_size, memory_info
export prepare_call!, exports_count, export_name, export_pc
export read_framebuffer_rgb24!

end # module
