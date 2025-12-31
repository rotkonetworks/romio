# CoreVM File System Encoding
# This is corevm-host specific, not part of JAM graypaper spec.
# Reverse engineered from jamt/polkajam binaries.

# Requires: Blake2b! from crypto/Blake2b.jl, encode_jam_compact from encoding/jam.jl

const COREVM_DEFAULT_BLOCK_SIZE = 4194296  # ~4MB

"""
Compute CoreVM file hash matching corevm-host MainBlock encoding.

CoreVM uses a block-based file encoding for the preimage store:
  MainBlock = NodeKind(1) + Compact(file_size) + Compact(block_size) + Vec<BlockRef> + inline_data

Where:
  - NodeKind: 0 = File, 1 = Dir
  - file_size: total size of the file data
  - block_size: default 4194296 (~4MB)
  - Vec<BlockRef>: list of references to continuation blocks
  - BlockRef = service_id(4 bytes LE) + hash(32 bytes)
  - inline_data: first chunk of data that fits in the MainBlock

For files smaller than block_size (minus header overhead), the entire file is stored
inline in a single MainBlock with an empty Vec<BlockRef>.

For larger files:
1. Calculate header overhead including BlockRef count
2. Store as much data as fits inline (block_size - header_size)
3. Hash remaining data chunks and include as BlockRefs
4. BlockRefs are ordered: service_id (4 bytes, always 0) + hash (32 bytes)

The MainBlock is always exactly block_size bytes for files >= block_size.
The hash is computed as blake2b-256 over the entire encoded MainBlock.
"""
function corevm_file_hash(data::Vector{UInt8}; block_size::Integer=COREVM_DEFAULT_BLOCK_SIZE, service_id::UInt32=UInt32(0))::Vector{UInt8}
    file_size = length(data)

    function calc_header_size(num_blockrefs::Int)
        return 1 + length(encode_jam_compact(file_size)) + length(encode_jam_compact(block_size)) +
               length(encode_jam_compact(num_blockrefs)) + num_blockrefs * 36
    end

    # For small files that fit in a single block
    header_size_zero = calc_header_size(0)
    if file_size <= block_size - header_size_zero
        buf = IOBuffer()
        write(buf, UInt8(0x00))  # NodeKind::File
        write(buf, encode_jam_compact(file_size))
        write(buf, encode_jam_compact(block_size))
        write(buf, UInt8(0x00))  # Empty Vec<BlockRef>
        write(buf, data)
        encoded = take!(buf)

        output = zeros(UInt8, 32)
        Blake2b!(output, 32, UInt8[], 0, encoded, length(encoded))
        return output
    end

    # For large files: iteratively determine number of continuation blocks
    num_continuations = 1
    while true
        header_size = calc_header_size(num_continuations)
        first_block_capacity = block_size - header_size
        remaining_data = file_size - first_block_capacity
        needed_continuations = max(1, ceil(Int, remaining_data / block_size))

        if needed_continuations == num_continuations
            break
        end
        num_continuations = needed_continuations
        if num_continuations > 1000
            error("Too many continuation blocks needed")
        end
    end

    header_size = calc_header_size(num_continuations)
    first_block_capacity = block_size - header_size

    # Compute hashes for each continuation block (raw data, not MainBlock encoded)
    continuation_hashes = Vector{Vector{UInt8}}()
    offset = first_block_capacity + 1
    for i in 1:num_continuations
        chunk_end = min(offset + block_size - 1, file_size)
        chunk = data[offset:chunk_end]

        chunk_hash = zeros(UInt8, 32)
        Blake2b!(chunk_hash, 32, UInt8[], 0, chunk, length(chunk))
        push!(continuation_hashes, chunk_hash)

        offset = chunk_end + 1
    end

    # Build MainBlock
    buf = IOBuffer()
    write(buf, UInt8(0x00))  # NodeKind::File
    write(buf, encode_jam_compact(file_size))
    write(buf, encode_jam_compact(block_size))
    write(buf, encode_jam_compact(num_continuations))

    # BlockRefs: service_id (4 bytes LE) + hash (32 bytes)
    sid_bytes = reinterpret(UInt8, [service_id])
    for hash in continuation_hashes
        write(buf, sid_bytes)
        write(buf, hash)
    end

    write(buf, data[1:first_block_capacity])
    main_block = take!(buf)

    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, main_block, length(main_block))
    return output
end

"""
Encode a file as CoreVM MainBlock and return the encoded MainBlock, continuation blocks, and hash.

Returns: (main_block, continuation_blocks, hash)
- main_block: The encoded MainBlock (always block_size bytes for large files)
- continuation_blocks: Vector of raw data chunks for continuation blocks
- hash: blake2b-256 hash of the MainBlock
"""
function encode_corevm_file(data::Vector{UInt8}; block_size::Integer=COREVM_DEFAULT_BLOCK_SIZE, service_id::UInt32=UInt32(0))::Tuple{Vector{UInt8}, Vector{Vector{UInt8}}, Vector{UInt8}}
    file_size = length(data)

    function calc_header_size(num_blockrefs::Int)
        return 1 + length(encode_jam_compact(file_size)) + length(encode_jam_compact(block_size)) +
               length(encode_jam_compact(num_blockrefs)) + num_blockrefs * 36
    end

    header_size_zero = calc_header_size(0)
    if file_size <= block_size - header_size_zero
        buf = IOBuffer()
        write(buf, UInt8(0x00))
        write(buf, encode_jam_compact(file_size))
        write(buf, encode_jam_compact(block_size))
        write(buf, UInt8(0x00))
        write(buf, data)
        encoded = take!(buf)

        output = zeros(UInt8, 32)
        Blake2b!(output, 32, UInt8[], 0, encoded, length(encoded))
        return (encoded, Vector{UInt8}[], output)
    end

    num_continuations = 1
    while true
        header_size = calc_header_size(num_continuations)
        first_block_capacity = block_size - header_size
        remaining_data = file_size - first_block_capacity
        needed = max(1, ceil(Int, remaining_data / block_size))
        if needed == num_continuations
            break
        end
        num_continuations = needed
        if num_continuations > 1000
            error("Too many continuation blocks needed")
        end
    end

    header_size = calc_header_size(num_continuations)
    first_block_capacity = block_size - header_size

    continuation_blocks = Vector{Vector{UInt8}}()
    continuation_hashes = Vector{Vector{UInt8}}()
    offset = first_block_capacity + 1
    for i in 1:num_continuations
        chunk_end = min(offset + block_size - 1, file_size)
        chunk = data[offset:chunk_end]
        push!(continuation_blocks, chunk)

        chunk_hash = zeros(UInt8, 32)
        Blake2b!(chunk_hash, 32, UInt8[], 0, chunk, length(chunk))
        push!(continuation_hashes, chunk_hash)

        offset = chunk_end + 1
    end

    buf = IOBuffer()
    write(buf, UInt8(0x00))
    write(buf, encode_jam_compact(file_size))
    write(buf, encode_jam_compact(block_size))
    write(buf, encode_jam_compact(num_continuations))

    sid_bytes = reinterpret(UInt8, [service_id])
    for hash in continuation_hashes
        write(buf, sid_bytes)
        write(buf, hash)
    end

    write(buf, data[1:first_block_capacity])
    main_block = take!(buf)

    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, main_block, length(main_block))

    return (main_block, continuation_blocks, output)
end

"""
Directory entry for CoreVM filesystem.
"""
struct CorevmDirEntry
    name::String
    service_id::UInt32
    hash::Vector{UInt8}
end

"""
Encode a directory as CoreVM MainBlock with NodeKind::Dir.

Directory encoding (reverse engineered from jamt):
  MainBlock = NodeKind(1) + Compact(entries_size) + Compact(block_size) + Vec<BlockRef> + dir_entries
  dir_entries = Compact(entry_count) + Vec<DirEntry>
  DirEntry = Compact(name_len) + name_bytes + service_id(4 bytes LE) + hash(32 bytes)

Returns: (encoded_mainblock, hash)
"""
function encode_corevm_dir(entries::Vector{CorevmDirEntry}; block_size::Integer=COREVM_DEFAULT_BLOCK_SIZE, service_id::UInt32=UInt32(0))::Tuple{Vector{UInt8}, Vector{UInt8}}
    # First encode the directory entries
    entries_buf = IOBuffer()
    write(entries_buf, encode_jam_compact(length(entries)))

    # Sort entries by name for deterministic ordering
    sorted_entries = sort(entries, by=e->e.name)

    for entry in sorted_entries
        name_bytes = Vector{UInt8}(entry.name)
        write(entries_buf, encode_jam_compact(length(name_bytes)))
        write(entries_buf, name_bytes)
        write(entries_buf, reinterpret(UInt8, [entry.service_id]))
        write(entries_buf, entry.hash)
    end
    dir_entries = take!(entries_buf)

    # Wrap as MainBlock with NodeKind::Dir
    buf = IOBuffer()
    write(buf, UInt8(0x01))  # NodeKind::Dir
    write(buf, encode_jam_compact(length(dir_entries)))
    write(buf, encode_jam_compact(block_size))
    write(buf, UInt8(0x00))  # Empty Vec<BlockRef> (directories don't span blocks)
    write(buf, dir_entries)
    main_block = take!(buf)

    output = zeros(UInt8, 32)
    Blake2b!(output, 32, UInt8[], 0, main_block, length(main_block))
    return (main_block, output)
end

"""
Compute CoreVM directory hash from a local filesystem directory.

Recursively encodes files and subdirectories, returning the root hash.
"""
function corevm_dir_hash(path::String; block_size::Integer=COREVM_DEFAULT_BLOCK_SIZE, service_id::UInt32=UInt32(0))::Vector{UInt8}
    if !isdir(path)
        error("Path is not a directory: $path")
    end

    entries = CorevmDirEntry[]

    for name in readdir(path)
        full_path = joinpath(path, name)
        if isfile(full_path)
            data = read(full_path)
            file_hash = corevm_file_hash(data; block_size=block_size, service_id=service_id)
            push!(entries, CorevmDirEntry(name, service_id, file_hash))
        elseif isdir(full_path)
            dir_hash = corevm_dir_hash(full_path; block_size=block_size, service_id=service_id)
            push!(entries, CorevmDirEntry(name, service_id, dir_hash))
        end
        # Skip symlinks and other special files
    end

    _, hash = encode_corevm_dir(entries; block_size=block_size, service_id=service_id)
    return hash
end

"""
CoreVM execution environment reference (BlockRef).
Used for program, root_dir in ExecEnv.
"""
struct CorevmBlockRef
    service_id::UInt32
    hash::Vector{UInt8}
end

"""
CoreVM execution environment.

ExecEnv encoding (reverse engineered from jamt):
  ExecEnv = program(BlockRef) + root_dir(Maybe<BlockRef>) + args(Vec<String>) + env(Vec<(String, String)>)

Where:
  - program: BlockRef to the PVM program blob
  - root_dir: Optional BlockRef to root filesystem directory
  - args: Command line arguments
  - env: Environment variables as key-value pairs
"""
struct CorevmExecEnv
    program::CorevmBlockRef
    root_dir::Union{Nothing, CorevmBlockRef}
    args::Vector{String}
    env::Vector{Tuple{String, String}}
end

"""
Encode a BlockRef.
"""
function encode_blockref(ref::CorevmBlockRef)::Vector{UInt8}
    buf = IOBuffer()
    write(buf, reinterpret(UInt8, [ref.service_id]))
    write(buf, ref.hash)
    return take!(buf)
end

"""
Encode ExecEnv for CoreVM work item payload.

Returns the encoded bytes.
"""
function encode_corevm_execenv(env::CorevmExecEnv)::Vector{UInt8}
    buf = IOBuffer()

    # program: BlockRef
    write(buf, encode_blockref(env.program))

    # root_dir: Maybe<BlockRef>
    if env.root_dir === nothing
        write(buf, UInt8(0x00))
    else
        write(buf, UInt8(0x01))
        write(buf, encode_blockref(env.root_dir))
    end

    # args: Vec<String>
    write(buf, encode_jam_compact(length(env.args)))
    for arg in env.args
        arg_bytes = Vector{UInt8}(arg)
        write(buf, encode_jam_compact(length(arg_bytes)))
        write(buf, arg_bytes)
    end

    # env: Vec<(String, String)>
    write(buf, encode_jam_compact(length(env.env)))
    for (key, value) in env.env
        key_bytes = Vector{UInt8}(key)
        value_bytes = Vector{UInt8}(value)
        write(buf, encode_jam_compact(length(key_bytes)))
        write(buf, key_bytes)
        write(buf, encode_jam_compact(length(value_bytes)))
        write(buf, value_bytes)
    end

    return take!(buf)
end
