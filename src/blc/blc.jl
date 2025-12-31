# Binary Lambda Calculus (BLC) Evaluator
# Based on Justine Tunney's 383-byte implementation
#
# BLC encoding:
#   00        = abstraction (λ)
#   01        = application
#   1...10    = variable (de Bruijn index, count 1s)
#
# This is a Krivine machine implementation with lazy evaluation.

module BLC

export parse_blc, eval_blc, encode_blc, Term, Abs, App, Var

# AST representation
abstract type Term end

struct Var <: Term
    index::Int  # de Bruijn index (0-based)
end

struct Abs <: Term
    body::Term
end

struct App <: Term
    func::Term
    arg::Term
end

# Runtime representation for Krivine machine
abstract type Value end

struct Closure <: Value
    term::Term
    env::Vector{Value}
end

struct Thunk <: Value
    term::Term
    env::Vector{Value}
end

# Bit stream for parsing
mutable struct BitStream
    data::Vector{UInt8}
    byte_pos::Int
    bit_pos::Int  # 0-7, MSB first
end

BitStream(data::Vector{UInt8}) = BitStream(data, 1, 0)

function read_bit!(bs::BitStream)::Bool
    if bs.byte_pos > length(bs.data)
        error("unexpected end of input")
    end
    byte = bs.data[bs.byte_pos]
    bit = (byte >> (7 - bs.bit_pos)) & 1
    bs.bit_pos += 1
    if bs.bit_pos == 8
        bs.bit_pos = 0
        bs.byte_pos += 1
    end
    return bit == 1
end

function bits_read(bs::BitStream)::Int
    return (bs.byte_pos - 1) * 8 + bs.bit_pos
end

# Parse BLC binary format
function parse_blc(data::Vector{UInt8})::Term
    bs = BitStream(data)
    term = parse_term!(bs)
    return term
end

function parse_term!(bs::BitStream)::Term
    b1 = read_bit!(bs)

    if !b1  # starts with 0
        b2 = read_bit!(bs)
        if !b2  # 00 = abstraction
            body = parse_term!(bs)
            return Abs(body)
        else    # 01 = application
            func = parse_term!(bs)
            arg = parse_term!(bs)
            return App(func, arg)
        end
    else  # starts with 1 = variable
        # Count 1s until we hit 0
        index = 0
        while read_bit!(bs)
            index += 1
        end
        return Var(index)
    end
end

# Encode term to BLC binary
function encode_blc(term::Term)::Vector{UInt8}
    bits = Bool[]
    encode_term!(bits, term)
    # Pad to byte boundary
    while length(bits) % 8 != 0
        push!(bits, false)
    end
    # Convert to bytes
    bytes = UInt8[]
    for i in 1:8:length(bits)
        byte = UInt8(0)
        for j in 0:7
            if bits[i + j]
                byte |= (1 << (7 - j))
            end
        end
        push!(bytes, byte)
    end
    return bytes
end

function encode_term!(bits::Vector{Bool}, term::Term)
    if term isa Abs
        push!(bits, false, false)  # 00
        encode_term!(bits, term.body)
    elseif term isa App
        push!(bits, false, true)   # 01
        encode_term!(bits, term.func)
        encode_term!(bits, term.arg)
    elseif term isa Var
        for _ in 1:term.index+1
            push!(bits, true)      # 1s for index
        end
        push!(bits, false)         # terminating 0
    end
end

# Krivine machine evaluation (call-by-name)
function eval_blc(term::Term; max_steps::Int=10000)::Term
    env = Value[]
    stack = Thunk[]
    current = term
    steps = 0

    while steps < max_steps
        steps += 1

        if current isa App
            # Push argument as thunk onto stack
            push!(stack, Thunk(current.arg, copy(env)))
            current = current.func

        elseif current isa Abs
            if isempty(stack)
                # No more arguments, we're done
                # Reconstruct term from closure
                return reconstruct(current, env)
            else
                # Apply: pop thunk from stack, extend environment
                thunk = pop!(stack)
                pushfirst!(env, thunk)
                current = current.body
            end

        elseif current isa Var
            if current.index >= length(env)
                error("unbound variable: $(current.index)")
            end
            val = env[current.index + 1]
            if val isa Thunk
                # Force thunk
                current = val.term
                env = val.env
            elseif val isa Closure
                current = val.term
                env = val.env
            end
        end
    end

    error("evaluation exceeded max steps")
end

# Reconstruct a term from closure (for returning results)
function reconstruct(term::Term, env::Vector{Value})::Term
    if term isa Var
        if term.index < length(env)
            val = env[term.index + 1]
            if val isa Thunk
                return reconstruct(val.term, val.env)
            elseif val isa Closure
                return reconstruct(val.term, val.env)
            end
        end
        return term
    elseif term isa Abs
        # Can't fully reconstruct without more work
        return term
    elseif term isa App
        return App(reconstruct(term.func, env), reconstruct(term.arg, env))
    end
    return term
end

# Pretty print
function Base.show(io::IO, t::Var)
    print(io, t.index)
end

function Base.show(io::IO, t::Abs)
    print(io, "λ", t.body)
end

function Base.show(io::IO, t::App)
    print(io, "(", t.func, " ", t.arg, ")")
end

# Common combinators
const I = Abs(Var(0))                           # λx.x
const K = Abs(Abs(Var(1)))                      # λx.λy.x
const S = Abs(Abs(Abs(App(App(Var(2), Var(0)), App(Var(1), Var(0))))))  # λx.λy.λz.xz(yz)

# Church numerals
church(n::Int) = Abs(Abs(foldr((_, acc) -> App(Var(1), acc), 1:n; init=Var(0))))

# Church booleans
const TRUE = K                                   # λx.λy.x
const FALSE = Abs(Abs(Var(0)))                  # λx.λy.y

end # module
