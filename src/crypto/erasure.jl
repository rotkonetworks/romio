# Erasure coding for JAM
module Erasure

using BinaryReedSolomon
using BinaryFields
import BinaryReedSolomon: ReedSolomonEncoding, reed_solomon, encode

# JAM uses RS(512, 1023) in GF(2^16)
struct JAMErasure
    rs::ReedSolomonEncoding{BinaryElem16}
end

function JAMErasure()
    # create encoder for JAM's parameters
    rs = reed_solomon(BinaryElem16, 512, 1024)
    return JAMErasure(rs)
end

function encode_erasure(enc::JAMErasure, data::Vector{UInt8})
    # split data into chunks for encoding
    # each chunk is 2 bytes (for GF(2^16))
    chunk_size = 2
    num_chunks = div(length(data), chunk_size)
    
    @assert num_chunks == 512 "Data must be exactly $(512 * 2) bytes"
    
    # convert to field elements
    message = BinaryElem16[]
    for i in 1:chunk_size:length(data)
        chunk = data[i:min(i+1, end)]
        val = UInt16(chunk[1]) | (UInt16(get(chunk, 2, 0)) << 8)
        push!(message, BinaryElem16(val))
    end
    
    # encode
    encoded = encode(enc.rs, message)
    
    # convert back to bytes
    result = UInt8[]
    for elem in encoded
        val = BinaryFields.binary_val(elem)
        push!(result, UInt8(val & 0xFF))
        push!(result, UInt8(val >> 8))
    end
    
    return result
end

export JAMErasure, encode_erasure

end
