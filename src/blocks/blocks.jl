# block structure combining header and extrinsic

struct Block
    header::Header
    extrinsic::Extrinsic
end

# helper to hash a header
function hash_header(header::Header)::Hash
    # encode header and hash
    # placeholder - need proper codec
    return H(Vector{UInt8}("header"))
end
