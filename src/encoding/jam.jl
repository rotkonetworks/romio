# JAM Serialization Codec
# Per graypaper section on Serialization (Appendix A.2)

"""
Encode natural number using JAM compact encoding.
Per graypaper equation for general natural number serialization:

encode(x) =
  [0] if x = 0
  [2^8 - 2^(8-l) + x/(2^(8l))] ++ encode_l(x mod 2^(8l))  if exists l in N_8: 2^(7l) <= x < 2^(7(l+1))
  [2^8-1] ++ encode_8(x)  if x < 2^64

This encodes values up to 2^64 into 1-9 bytes.
"""
function encode_jam_compact(x::Integer)::Vector{UInt8}
    if x == 0
        return [UInt8(0)]
    elseif x < 2^7  # l=0: x < 128
        return [UInt8(x)]
    elseif x < 2^14  # l=1: 128 <= x < 16384
        l = 1
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        suffix = UInt8(x % 2^(8*l))
        return [prefix, suffix]
    elseif x < 2^21  # l=2: 16384 <= x < 2097152
        l = 2
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        bytes = reinterpret(UInt8, [UInt16(x % 2^(8*l))])
        return vcat([prefix], bytes)
    elseif x < 2^28  # l=3:
        l = 3
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        val = UInt32(x % 2^(8*l))
        bytes = [UInt8((val >> (8*i)) & 0xff) for i in 0:2]
        return vcat([prefix], bytes)
    elseif x < 2^35  # l=4:
        l = 4
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        val = UInt64(x % 2^(8*l))
        bytes = [UInt8((val >> (8*i)) & 0xff) for i in 0:3]
        return vcat([prefix], bytes)
    elseif x < 2^42  # l=5:
        l = 5
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        val = UInt64(x % 2^(8*l))
        bytes = [UInt8((val >> (8*i)) & 0xff) for i in 0:4]
        return vcat([prefix], bytes)
    elseif x < 2^49  # l=6:
        l = 6
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        val = UInt64(x % 2^(8*l))
        bytes = [UInt8((val >> (8*i)) & 0xff) for i in 0:5]
        return vcat([prefix], bytes)
    elseif x < 2^56  # l=7:
        l = 7
        prefix = UInt8(2^8 - 2^(8-l) + div(x, 2^(8*l)))
        val = UInt64(x % 2^(8*l))
        bytes = [UInt8((val >> (8*i)) & 0xff) for i in 0:6]
        return vcat([prefix], bytes)
    else  # x < 2^64: full 8-byte encoding
        return vcat([UInt8(255)], reinterpret(UInt8, [UInt64(x)]))
    end
end

"""
Encode variable-length blob using JAM var(x) notation.
Per graypaper: var(x) ≡ (len(x), x) thus encode(var(x)) ≡ encode(len(x)) ++ encode(x)
"""
function encode_jam_blob(data::Vector{UInt8})::Vector{UInt8}
    return vcat(encode_jam_compact(length(data)), data)
end

"""
Encode optional value using JAM maybe(x) notation.
Per graypaper: maybe(x) = 0 if x = none, (1, x) otherwise
"""
function encode_jam_optional(value::Union{Nothing, Vector{UInt8}})::Vector{UInt8}
    if value === nothing
        return [UInt8(0)]
    else
        return vcat([UInt8(1)], value)
    end
end
