# bandersnatch-ffi

C FFI for Bandersnatch ring VRF operations. Used by JAM for anonymous ticket verification.

## Build

```bash
cargo build --release
```

Output: `target/release/libbandersnatch_ffi.so`

Note: The SRS parameters file (`parameters/zcash-srs-2-11-uncompressed.bin`) is embedded at compile time.

## Functions

### Version

```c
uint32_t bandersnatch_version(void);  // major<<16 | minor<<8 | patch
```

### Ticket ID from VRF Output

```c
int32_t bandersnatch_compute_ticket_id(
    const uint8_t* output,      // 32 bytes, compressed curve point
    uint8_t* ticket_id          // 32 bytes output
);
```

### Ring Verification

```c
// Create verifier (expensive, cache this)
void* bandersnatch_ring_verifier_new(
    const uint8_t* commitment,
    size_t commitment_len,
    size_t ring_size
);

// Verify signature
int32_t bandersnatch_ring_verify(
    const void* verifier,
    const uint8_t* input_data,  // VRF input (entropy || attempt)
    size_t input_len,
    const uint8_t* signature,   // 784 bytes: 32 output + 752 proof
    size_t signature_len,
    uint8_t* ticket_id_out      // optional, 32 bytes
);

void bandersnatch_ring_verifier_free(void* verifier);
```

### Commitment Generation

```c
int32_t bandersnatch_compute_ring_commitment(
    const uint8_t* keys,        // num_keys * 32 bytes
    size_t num_keys,
    uint8_t* commitment_out,
    size_t* commitment_len      // in: buffer size, out: actual size
);
```

## Error Codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| -1 | Null pointer |
| -2 | Invalid curve point |
| -3 | Invalid VRF output |
| -4 | Invalid proof |
| -5 | Verification failed |
| -6 | Invalid input data |

## Julia

```julia
const lib = Libdl.dlopen("libbandersnatch_ffi.so")

# verify ring signature
verifier = @ccall $(dlsym(lib, :bandersnatch_ring_verifier_new))(
    commitment::Ptr{UInt8}, length(commitment)::Csize_t, ring_size::Csize_t
)::Ptr{Cvoid}

ticket = Vector{UInt8}(undef, 32)
result = @ccall $(dlsym(lib, :bandersnatch_ring_verify))(
    verifier::Ptr{Cvoid},
    input::Ptr{UInt8}, length(input)::Csize_t,
    sig::Ptr{UInt8}, length(sig)::Csize_t,
    ticket::Ptr{UInt8}
)::Cint

@ccall $(dlsym(lib, :bandersnatch_ring_verifier_free))(verifier::Ptr{Cvoid})::Cvoid
```

## License

MIT OR Apache-2.0
