# paritydb-ffi

C FFI for ParityDB key-value storage. Write overlay with atomic commit/rollback.

## Build

```bash
cargo build --release
```

Output: `target/release/libparitydb_ffi.so`

## Functions

### Lifecycle

```c
uint32_t pdb_version(void);  // major<<16 | minor<<8 | patch

void* pdb_open(const char* path, int32_t* error_out);
int32_t pdb_close(void* handle);
int32_t pdb_is_valid(void* handle);  // 1 if valid
```

### Read/Write

```c
// Get value size (-1 if not found)
int64_t pdb_get_size(void* handle, uint8_t column, const uint8_t* key, size_t key_len);

// Read value (returns 0=ok, 1=not found, <0=error)
int32_t pdb_get(
    void* handle, uint8_t column,
    const uint8_t* key, size_t key_len,
    uint8_t* value_out, size_t* value_len  // in: buffer size, out: actual size
);

// Write to overlay (value_ptr=NULL to delete)
int32_t pdb_put(
    void* handle, uint8_t column,
    const uint8_t* key, size_t key_len,
    const uint8_t* value, size_t value_len
);

int32_t pdb_commit(void* handle);    // flush overlay to disk
int32_t pdb_rollback(void* handle);  // discard overlay
int64_t pdb_pending_count(void* handle, int8_t column);  // -1 for all columns
```

### Iteration

```c
// Callback returns 1 to continue, 0 to stop
typedef int32_t (*pdb_iterate_cb)(const uint8_t* key, size_t key_len,
                                   const uint8_t* val, size_t val_len);
typedef int32_t (*pdb_keys_cb)(const uint8_t* key, size_t key_len);

int64_t pdb_iterate(void* handle, uint8_t column, pdb_iterate_cb cb);
int64_t pdb_iterate_keys(void* handle, uint8_t column, pdb_keys_cb cb);
int64_t pdb_count(void* handle, uint8_t column);
```

## Columns

5 columns by default (configurable via `PDB_NUM_COLUMNS`):

| Col | JAM Usage |
|-----|-----------|
| 0 | Service state |
| 1 | Authorizations |
| 2 | Recent blocks |
| 3 | Validator keys |
| 4 | Statistics |

## Error Codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Not found |
| -1 | Null pointer |
| -2 | Invalid UTF-8 path |
| -3 | Open failed |
| -4 | Write failed |
| -5 | Read failed |
| -6 | Invalid handle |
| -7 | Invalid column |

## Julia

```julia
const lib = Libdl.dlopen("libparitydb_ffi.so")

err = Ref{Cint}(0)
db = @ccall $(dlsym(lib, :pdb_open))("/tmp/jam.db"::Cstring, err::Ptr{Cint})::Ptr{Cvoid}

# write
key = Vector{UInt8}("mykey")
val = Vector{UInt8}("myvalue")
@ccall $(dlsym(lib, :pdb_put))(
    db::Ptr{Cvoid}, 0::UInt8,
    key::Ptr{UInt8}, length(key)::Csize_t,
    val::Ptr{UInt8}, length(val)::Csize_t
)::Cint
@ccall $(dlsym(lib, :pdb_commit))(db::Ptr{Cvoid})::Cint

# read
buf = Vector{UInt8}(undef, 256)
len = Ref{Csize_t}(256)
result = @ccall $(dlsym(lib, :pdb_get))(
    db::Ptr{Cvoid}, 0::UInt8,
    key::Ptr{UInt8}, length(key)::Csize_t,
    buf::Ptr{UInt8}, len::Ptr{Csize_t}
)::Cint

@ccall $(dlsym(lib, :pdb_close))(db::Ptr{Cvoid})::Cint
```

## License

MIT OR Apache-2.0
