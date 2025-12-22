# ENOMT FFI wrapper for Julia
# provides fast merkle trie operations via nomt with blake2b-256 hashing

module ENOMT

using Libdl

# find and load the shared library, cache function pointers
const FFI = let
    lib_path = joinpath(@__DIR__, "..", "..", "deps", "enomt-ffi", "target", "release")
    lib_name = Sys.iswindows() ? "enomt_ffi.dll" :
               Sys.isapple() ? "libenomt_ffi.dylib" : "libenomt_ffi.so"
    full_path = joinpath(lib_path, lib_name)

    if !isfile(full_path)
        error("ENOMT FFI library not found at $full_path. Run `cargo build --release` in deps/enomt-ffi/")
    end

    lib = dlopen(full_path)
    (
        lib = lib,
        init = dlsym(lib, :enomt_init),
        close = dlsym(lib, :enomt_close),
        root = dlsym(lib, :enomt_root),
        read = dlsym(lib, :enomt_read),
        write = dlsym(lib, :enomt_write),
        commit = dlsym(lib, :enomt_commit),
        rollback = dlsym(lib, :enomt_rollback),
        pending_count = dlsym(lib, :enomt_pending_count),
    )
end

# error codes
const OK = Int32(0)
const NOT_FOUND = Int32(1)
const ERR_NULL_PTR = Int32(-1)
const ERR_INVALID_STR = Int32(-2)
const ERR_OPEN_FAILED = Int32(-3)
const ERR_COMMIT_FAILED = Int32(-4)

# state
mutable struct ENOMTState
    initialized::Bool
    db_path::String
end

const STATE = ENOMTState(false, "")

# initialize nomt database at the given path
function init(path::String)::Bool
    if STATE.initialized
        close()
    end

    result = ccall(FFI.init, Int32, (Cstring,), path)
    if result == OK
        STATE.initialized = true
        STATE.db_path = path
        return true
    end
    return false
end

# close nomt database
function close()
    if STATE.initialized
        ccall(FFI.close, Cvoid, ())
        STATE.initialized = false
        STATE.db_path = ""
    end
end

# get current root hash (32 bytes)
function root()::Union{Vector{UInt8}, Nothing}
    if !STATE.initialized
        return nothing
    end

    root_buf = Vector{UInt8}(undef, 32)
    result = ccall(FFI.root, Int32, (Ptr{UInt8},), root_buf)

    if result == OK
        return root_buf
    end
    return nothing
end

# read value for a 32-byte key
function read(key::Vector{UInt8})::Union{Vector{UInt8}, Nothing}
    if !STATE.initialized || length(key) != 32
        return nothing
    end

    # preallocate reasonable buffer, most values are small
    max_value_size = 1024 * 1024
    value_buf = Vector{UInt8}(undef, max_value_size)
    value_len = Ref{Csize_t}(max_value_size)

    result = ccall(FFI.read, Int32,
                   (Ptr{UInt8}, Ptr{UInt8}, Ptr{Csize_t}),
                   key, value_buf, value_len)

    if result == OK
        return value_buf[1:value_len[]]
    elseif result == NOT_FOUND
        return nothing
    end
    return nothing
end

# write a key-value pair to the overlay (not committed yet)
# key must be 32 bytes, value can be any length (or nothing to delete)
function write!(key::Vector{UInt8}, value::Union{Vector{UInt8}, Nothing})::Bool
    if !STATE.initialized || length(key) != 32
        return false
    end

    if value === nothing
        result = ccall(FFI.write, Int32,
                       (Ptr{UInt8}, Ptr{UInt8}, Csize_t),
                       key, C_NULL, 0)
    else
        result = ccall(FFI.write, Int32,
                       (Ptr{UInt8}, Ptr{UInt8}, Csize_t),
                       key, value, length(value))
    end

    return result == OK
end

# commit all pending writes and return new root hash
function commit()::Union{Vector{UInt8}, Nothing}
    if !STATE.initialized
        return nothing
    end

    root_buf = Vector{UInt8}(undef, 32)
    result = ccall(FFI.commit, Int32, (Ptr{UInt8},), root_buf)

    if result == OK
        return root_buf
    end
    return nothing
end

# clear the in-memory overlay without committing
function rollback()::Bool
    if !STATE.initialized
        return false
    end

    result = ccall(FFI.rollback, Int32, ())
    return result == OK
end

# get number of pending writes in overlay
function pending_count()::Int
    if !STATE.initialized
        return -1
    end

    return Int(ccall(FFI.pending_count, Int64, ()))
end

# check if database is initialized
function is_initialized()::Bool
    return STATE.initialized
end

# batch write multiple key-value pairs
function batch_write!(pairs::Vector{Tuple{Vector{UInt8}, Union{Vector{UInt8}, Nothing}}})::Bool
    for (key, value) in pairs
        if !write!(key, value)
            return false
        end
    end
    return true
end

# compute state root from key-value pairs without persisting
# creates a temp db, writes everything, commits, then cleans up
function compute_root(pairs::Vector{Tuple{Vector{UInt8}, Vector{UInt8}}})::Union{Vector{UInt8}, Nothing}
    tmp_path = mktempdir()
    try
        if !init(tmp_path)
            return nothing
        end
        for (key, value) in pairs
            if !write!(key, value)
                return nothing
            end
        end
        return commit()
    finally
        close()
        rm(tmp_path, recursive=true, force=true)
    end
end

export init, close, root, read, write!, commit, rollback, pending_count
export is_initialized, batch_write!, compute_root

end # module ENOMT
