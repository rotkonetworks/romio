using Blake2

# JAM uses Blake2b-256
function H(data::Vector{UInt8})::Hash
    out = zeros(UInt8, 32)
    Blake2.Blake2b!(out, 32, UInt8[], 0, data, length(data))
    return Hash(out)
end

# Hash multiple items
function H(items...)::Hash
    combined = UInt8[]
    for item in items
        append!(combined, item)
    end
    return H(combined)
end
