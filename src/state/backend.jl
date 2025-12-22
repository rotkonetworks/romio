# State Backend Abstraction
# Provides unified interface for state storage with pluggable backends

module StateBackend

using Libdl

export AbstractBackend, InMemoryBackend, ParityDBBackend
export backend_init!, backend_close!, backend_get, backend_put!, backend_delete!
export backend_commit!, backend_rollback!, backend_pairs, backend_is_open
export Column, COL_SERVICE, COL_AUTH, COL_RECENT, COL_VALIDATORS, COL_STATS

# ============================================================================
# Column definitions for JAM state
# ============================================================================

@enum Column::UInt8 begin
    COL_SERVICE = 0     # Service state
    COL_AUTH = 1        # Authorizations
    COL_RECENT = 2      # Recent blocks
    COL_VALIDATORS = 3  # Validator keys
    COL_STATS = 4       # Statistics
end

# ============================================================================
# Abstract Backend Interface
# ============================================================================

abstract type AbstractBackend end

# Required methods for all backends
function backend_init!(backend::AbstractBackend, path::String)::Bool end
function backend_close!(backend::AbstractBackend) end
function backend_get(backend::AbstractBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Union{Vector{UInt8}, Nothing} end
function backend_put!(backend::AbstractBackend, key::Vector{UInt8}, value::Vector{UInt8}; column::Column=COL_SERVICE)::Bool end
function backend_delete!(backend::AbstractBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Bool end
function backend_commit!(backend::AbstractBackend)::Bool end
function backend_rollback!(backend::AbstractBackend)::Bool end
function backend_pairs(backend::AbstractBackend; column::Column=COL_SERVICE)::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}} end
function backend_is_open(backend::AbstractBackend)::Bool end

# ============================================================================
# In-Memory Backend (for testing and conformance)
# ============================================================================

mutable struct InMemoryBackend <: AbstractBackend
    # Per-column storage
    data::Vector{Dict{Vector{UInt8}, Vector{UInt8}}}
    pending::Vector{Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}}
    initialized::Bool
end

function InMemoryBackend()
    num_cols = 5
    InMemoryBackend(
        [Dict{Vector{UInt8}, Vector{UInt8}}() for _ in 1:num_cols],
        [Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}() for _ in 1:num_cols],
        false
    )
end

function backend_init!(backend::InMemoryBackend, path::String)::Bool
    num_cols = 5
    backend.data = [Dict{Vector{UInt8}, Vector{UInt8}}() for _ in 1:num_cols]
    backend.pending = [Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}() for _ in 1:num_cols]
    backend.initialized = true
    return true
end

function backend_close!(backend::InMemoryBackend)
    num_cols = 5
    backend.data = [Dict{Vector{UInt8}, Vector{UInt8}}() for _ in 1:num_cols]
    backend.pending = [Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}() for _ in 1:num_cols]
    backend.initialized = false
end

function backend_get(backend::InMemoryBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Union{Vector{UInt8}, Nothing}
    if !backend.initialized
        return nothing
    end
    col = Int(column) + 1  # 1-indexed
    # Check pending first
    if haskey(backend.pending[col], key)
        return backend.pending[col][key]  # May be nothing (deleted)
    end
    # Then check committed data
    return get(backend.data[col], key, nothing)
end

function backend_put!(backend::InMemoryBackend, key::Vector{UInt8}, value::Vector{UInt8}; column::Column=COL_SERVICE)::Bool
    if !backend.initialized
        return false
    end
    col = Int(column) + 1
    backend.pending[col][key] = value
    return true
end

function backend_delete!(backend::InMemoryBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Bool
    if !backend.initialized
        return false
    end
    col = Int(column) + 1
    backend.pending[col][key] = nothing
    return true
end

function backend_commit!(backend::InMemoryBackend)::Bool
    if !backend.initialized
        return false
    end
    for col in 1:length(backend.data)
        for (key, value) in backend.pending[col]
            if value === nothing
                delete!(backend.data[col], key)
            else
                backend.data[col][key] = value
            end
        end
        backend.pending[col] = Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}()
    end
    return true
end

function backend_rollback!(backend::InMemoryBackend)::Bool
    if !backend.initialized
        return false
    end
    for col in 1:length(backend.pending)
        backend.pending[col] = Dict{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}()
    end
    return true
end

function backend_pairs(backend::InMemoryBackend; column::Column=COL_SERVICE)::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}
    if !backend.initialized
        return Tuple{Vector{UInt8}, Vector{UInt8}}[]
    end
    col = Int(column) + 1
    # Merge committed and pending
    result = Dict{Vector{UInt8}, Vector{UInt8}}()
    for (k, v) in backend.data[col]
        result[k] = v
    end
    for (k, v) in backend.pending[col]
        if v === nothing
            delete!(result, k)
        else
            result[k] = v
        end
    end
    return [(k, v) for (k, v) in result]
end

function backend_is_open(backend::InMemoryBackend)::Bool
    return backend.initialized
end

# ============================================================================
# ParityDB Backend (for production)
# ============================================================================

# FFI function pointers - cached at module load time
mutable struct PdbFFI
    lib_handle::Ptr{Nothing}
    fn_open::Ptr{Nothing}
    fn_close::Ptr{Nothing}
    fn_is_valid::Ptr{Nothing}
    fn_get_size::Ptr{Nothing}
    fn_get::Ptr{Nothing}
    fn_put::Ptr{Nothing}
    fn_commit::Ptr{Nothing}
    fn_rollback::Ptr{Nothing}
    fn_pending_count::Ptr{Nothing}
    fn_count::Ptr{Nothing}
    loaded::Bool
end

const FFI = Ref{PdbFFI}()

function load_ffi!()
    lib_path = joinpath(@__DIR__, "..", "..", "deps", "paritydb-ffi", "target", "release")
    lib_name = Sys.iswindows() ? "paritydb_ffi.dll" :
               Sys.isapple() ? "libparitydb_ffi.dylib" : "libparitydb_ffi.so"
    full_path = joinpath(lib_path, lib_name)

    if !isfile(full_path)
        error("ParityDB FFI library not found at $full_path. Run `cargo build --release` in deps/paritydb-ffi/")
    end

    handle = dlopen(full_path)

    FFI[] = PdbFFI(
        handle,
        dlsym(handle, :pdb_open),
        dlsym(handle, :pdb_close),
        dlsym(handle, :pdb_is_valid),
        dlsym(handle, :pdb_get_size),
        dlsym(handle, :pdb_get),
        dlsym(handle, :pdb_put),
        dlsym(handle, :pdb_commit),
        dlsym(handle, :pdb_rollback),
        dlsym(handle, :pdb_pending_count),
        dlsym(handle, :pdb_count),
        true
    )
end

# Error codes
const PDB_OK = Int32(0)
const PDB_NOT_FOUND = Int32(1)

mutable struct ParityDBBackend <: AbstractBackend
    handle::Ptr{Nothing}  # PdbHandle*
    path::String
    initialized::Bool
end

function ParityDBBackend()
    if !isdefined(FFI, 1) || !FFI[].loaded
        load_ffi!()
    end
    return ParityDBBackend(C_NULL, "", false)
end

function backend_init!(backend::ParityDBBackend, path::String)::Bool
    if backend.initialized
        backend_close!(backend)
    end

    error_out = Ref{Int32}(0)
    handle = ccall(FFI[].fn_open, Ptr{Nothing}, (Cstring, Ptr{Int32}), path, error_out)

    if handle == C_NULL
        @warn "ParityDB open failed with error code: $(error_out[])"
        return false
    end

    backend.handle = handle
    backend.path = path
    backend.initialized = true
    return true
end

function backend_close!(backend::ParityDBBackend)
    if backend.initialized && backend.handle != C_NULL
        ccall(FFI[].fn_close, Int32, (Ptr{Nothing},), backend.handle)
        backend.handle = C_NULL
        backend.initialized = false
        backend.path = ""
    end
end

function backend_get(backend::ParityDBBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Union{Vector{UInt8}, Nothing}
    if !backend.initialized || backend.handle == C_NULL
        return nothing
    end

    col = UInt8(column)

    # First query the size
    size = ccall(FFI[].fn_get_size, Int64,
                 (Ptr{Nothing}, UInt8, Ptr{UInt8}, Csize_t),
                 backend.handle, col, key, length(key))

    if size < 0
        return nothing  # Not found or error
    end

    if size == 0
        return UInt8[]  # Empty value
    end

    # Allocate exact buffer size
    value_buf = Vector{UInt8}(undef, size)
    value_len = Ref{Csize_t}(size)

    result = ccall(FFI[].fn_get, Int32,
                   (Ptr{Nothing}, UInt8, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{Csize_t}),
                   backend.handle, col, key, length(key), value_buf, value_len)

    if result == PDB_OK
        return value_buf[1:value_len[]]
    end
    return nothing
end

function backend_put!(backend::ParityDBBackend, key::Vector{UInt8}, value::Vector{UInt8}; column::Column=COL_SERVICE)::Bool
    if !backend.initialized || backend.handle == C_NULL
        return false
    end

    col = UInt8(column)
    result = ccall(FFI[].fn_put, Int32,
                   (Ptr{Nothing}, UInt8, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                   backend.handle, col, key, length(key), value, length(value))
    return result == PDB_OK
end

function backend_delete!(backend::ParityDBBackend, key::Vector{UInt8}; column::Column=COL_SERVICE)::Bool
    if !backend.initialized || backend.handle == C_NULL
        return false
    end

    col = UInt8(column)
    result = ccall(FFI[].fn_put, Int32,
                   (Ptr{Nothing}, UInt8, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                   backend.handle, col, key, length(key), C_NULL, 0)
    return result == PDB_OK
end

function backend_commit!(backend::ParityDBBackend)::Bool
    if !backend.initialized || backend.handle == C_NULL
        return false
    end

    result = ccall(FFI[].fn_commit, Int32, (Ptr{Nothing},), backend.handle)
    return result == PDB_OK
end

function backend_rollback!(backend::ParityDBBackend)::Bool
    if !backend.initialized || backend.handle == C_NULL
        return false
    end

    result = ccall(FFI[].fn_rollback, Int32, (Ptr{Nothing},), backend.handle)
    return result == PDB_OK
end

function backend_pairs(backend::ParityDBBackend; column::Column=COL_SERVICE)::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}
    if !backend.initialized || backend.handle == C_NULL
        return Tuple{Vector{UInt8}, Vector{UInt8}}[]
    end

    # For now, we don't have a pairs iterator in FFI
    # This would require implementing pdb_iterate callback
    # Return empty for now - caller should maintain their own cache if needed
    @warn "backend_pairs not implemented for ParityDBBackend - use iteration callback"
    return Tuple{Vector{UInt8}, Vector{UInt8}}[]
end

function backend_is_open(backend::ParityDBBackend)::Bool
    if !backend.initialized || backend.handle == C_NULL
        return false
    end
    result = ccall(FFI[].fn_is_valid, Int32, (Ptr{Nothing},), backend.handle)
    return result == 1
end

function backend_count(backend::ParityDBBackend; column::Column=COL_SERVICE)::Int64
    if !backend.initialized || backend.handle == C_NULL
        return -1
    end
    col = UInt8(column)
    return ccall(FFI[].fn_count, Int64, (Ptr{Nothing}, UInt8), backend.handle, col)
end

function backend_pending_count(backend::ParityDBBackend; column::Int8=-1)::Int64
    if !backend.initialized || backend.handle == C_NULL
        return -1
    end
    return ccall(FFI[].fn_pending_count, Int64, (Ptr{Nothing}, Int8), backend.handle, column)
end

# ============================================================================
# StateStore - Unified interface wrapping any backend
# ============================================================================

mutable struct StateStore
    backend::AbstractBackend

    # Direct Dict access for compatibility with existing code
    # Syncs with backend on access
    data::Dict{Vector{UInt8}, Vector{UInt8}}
end

function StateStore(backend::AbstractBackend)
    return StateStore(backend, Dict{Vector{UInt8}, Vector{UInt8}}())
end

# Default to in-memory backend
function StateStore()
    backend = InMemoryBackend()
    backend_init!(backend, "")
    return StateStore(backend, Dict{Vector{UInt8}, Vector{UInt8}}())
end

# Sync data dict from backend
function sync_from_backend!(store::StateStore)
    pairs = backend_pairs(store.backend)
    store.data = Dict(pairs)
end

# Sync data dict to backend
function sync_to_backend!(store::StateStore)
    for (k, v) in store.data
        backend_put!(store.backend, k, v)
    end
    backend_commit!(store.backend)
end

end # module StateBackend
