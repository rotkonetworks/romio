# ParityDB FFI wrapper for Julia
# DEPRECATED: Use StateBackend module from backend.jl instead
# This module provides backward compatibility for existing code

module ParityDB

include("backend.jl")
using .StateBackend: ParityDBBackend, backend_init!, backend_close!, backend_get, backend_put!
using .StateBackend: backend_commit!, backend_rollback!, backend_pending_count, backend_is_open, COL_SERVICE

# Global backend instance for legacy API
const BACKEND = Ref{Union{Nothing, ParityDBBackend}}(nothing)

# Initialize ParityDB at the given path
function init(path::String)::Bool
    if BACKEND[] !== nothing
        close()
    end
    backend = ParityDBBackend()
    if backend_init!(backend, path)
        BACKEND[] = backend
        return true
    end
    return false
end

# Close ParityDB
function close()
    if BACKEND[] !== nothing
        backend_close!(BACKEND[])
        BACKEND[] = nothing
    end
end

# Get value for a key (any length)
function get(key::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    if BACKEND[] === nothing
        return nothing
    end
    return backend_get(BACKEND[], key; column=COL_SERVICE)
end

# Put a key-value pair (buffered, call commit() to persist)
function put!(key::Vector{UInt8}, value::Union{Vector{UInt8}, Nothing})::Bool
    if BACKEND[] === nothing
        return false
    end
    if value === nothing
        # Delete - use empty value and null ptr in FFI
        return StateBackend.backend_delete!(BACKEND[], key; column=COL_SERVICE)
    else
        return backend_put!(BACKEND[], key, value; column=COL_SERVICE)
    end
end

# Commit all pending writes
function commit()::Bool
    if BACKEND[] === nothing
        return false
    end
    return backend_commit!(BACKEND[])
end

# Rollback pending writes
function rollback()::Bool
    if BACKEND[] === nothing
        return false
    end
    return backend_rollback!(BACKEND[])
end

# Get number of pending writes
function pending_count()::Int
    if BACKEND[] === nothing
        return -1
    end
    return Int(backend_pending_count(BACKEND[]; column=Int8(-1)))
end

# Check if initialized
function is_open()::Bool
    if BACKEND[] === nothing
        return false
    end
    return backend_is_open(BACKEND[])
end

# Batch put multiple key-value pairs
function batch_put!(pairs::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}})::Bool
    for (key, value) in pairs
        if !put!(key, value)
            return false
        end
    end
    return true
end

# Get all key-value pairs (for BPMT computation)
# Note: This requires iteration callback implementation
function get_all()::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}}
    if BACKEND[] === nothing
        return Tuple{Vector{UInt8}, Vector{UInt8}}[]
    end
    # Not implemented in new backend - return empty
    return Tuple{Vector{UInt8}, Vector{UInt8}}[]
end

export init, close, get, put!, commit, rollback, pending_count, is_open
export batch_put!, get_all

end # module ParityDB
