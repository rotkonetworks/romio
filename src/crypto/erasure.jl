using BinaryReedSolomon
using BinaryFields

# JAM uses RS(342, 1023) in GF(2^16)
struct JAMErasure
    rs::ReedSolomonEncoding{BinaryElem16}
end

function JAMErasure()
    # Create encoder for JAM's parameters
    rs = reed_solomon(BinaryElem16, DATA_SHARDS, TOTAL_SHARDS)
    return JAMErasure(rs)
end

function encode_erasure(enc::JAMErasure, data::Vector{UInt8})
    # Split data into chunks for encoding
    # Each chunk is 2 bytes (for GF(2^16))
    chunk_size = 2
    num_chunks = div(length(data), chunk_size)
    
    @assert num_chunks == DATA_SHARDS "Data must be exactly $(DATA_SHARDS * 2) bytes"
    
    # Convert to field elements
    message = BinaryElem16[]
    for i in 1:chunk_size:length(data)
        chunk = data[i:min(i+1, end)]
        val = UInt16(chunk[1]) | (UInt16(get(chunk, 2, 0)) << 8)
        push!(message, BinaryElem16(val))
    end
    
    # Encode
    encoded = encode(enc.rs, message)
    
    # Convert back to bytes
    result = UInt8[]
    for elem in encoded
        val = BinaryFields.binary_val(elem)
        push!(result, UInt8(val & 0xFF))
        push!(result, UInt8(val >> 8))
    end
    
    return result
end
