# BLC JAM Service - Minimal lambda calculus service for JAM
#
# This implements a JAM service where:
# - State is a BLC-encoded lambda term
# - Work items are BLC-encoded lambda terms
# - accumulate applies work item to state: new_state = eval(work_item state)
#
# The entire service logic is: state' = β-reduce(work_item state)

module BLCService

include("blc.jl")
using .BLC

export BLCAccumulator, accumulate!, refine, encode_state, decode_state

# Service state: just a lambda term encoded as bytes
mutable struct BLCAccumulator
    state::Vector{UInt8}     # BLC-encoded term
    max_reductions::Int      # gas limit for evaluation
end

BLCAccumulator() = BLCAccumulator(encode_blc(BLC.I), 10000)  # default: identity

function decode_state(acc::BLCAccumulator)::Term
    parse_blc(acc.state)
end

function encode_state(term::Term)::Vector{UInt8}
    encode_blc(term)
end

"""
    accumulate!(acc, work_item_bytes) -> success

Apply a BLC term (encoded in work_item_bytes) to the current state.
The new state becomes: eval(work_item current_state)

Returns true on success, false on evaluation error.
"""
function accumulate!(acc::BLCAccumulator, work_item::Vector{UInt8})::Bool
    try
        # Parse work item as lambda term
        work_term = parse_blc(work_item)

        # Parse current state
        state_term = parse_blc(acc.state)

        # Apply work item to state
        application = App(work_term, state_term)

        # Evaluate (with gas limit)
        result = eval_blc(application; max_steps=acc.max_reductions)

        # Encode result as new state
        acc.state = encode_blc(result)

        return true
    catch e
        # Evaluation failed (unbound var, exceeded steps, parse error)
        @warn "BLC accumulate failed: $e"
        return false
    end
end

"""
    refine(acc, payload) -> output_bytes

Read-only computation on current state.
Applies payload term to state and returns encoded result.
Does not modify state.
"""
function refine(acc::BLCAccumulator, payload::Vector{UInt8})::Vector{UInt8}
    try
        work_term = parse_blc(payload)
        state_term = parse_blc(acc.state)
        application = App(work_term, state_term)
        result = eval_blc(application; max_steps=acc.max_reductions)
        return encode_blc(result)
    catch e
        return UInt8[]  # empty result on error
    end
end

# ============================================
# JAM Service Interface
# ============================================

# Service ID for BLC service
const BLC_SERVICE_ID = UInt32(100)

"""
Format for BLC service work items:
  - bytes 0-3: operation (0 = accumulate, 1 = refine)
  - bytes 4-7: term length
  - bytes 8+:  BLC-encoded term
"""
function handle_work_item(acc::BLCAccumulator, work_item::Vector{UInt8})::Vector{UInt8}
    if length(work_item) < 8
        return UInt8[]
    end

    op = reinterpret(UInt32, work_item[1:4])[1]
    term_len = reinterpret(UInt32, work_item[5:8])[1]

    if length(work_item) < 8 + term_len
        return UInt8[]
    end

    term_bytes = work_item[9:8+term_len]

    if op == 0  # accumulate
        success = accumulate!(acc, term_bytes)
        return success ? [0x01] : [0x00]
    elseif op == 1  # refine
        return refine(acc, term_bytes)
    else
        return UInt8[]
    end
end

# ============================================
# Example: Counter service using Church numerals
# ============================================

"""
Build a counter service that tracks a Church numeral.

Operations:
- INCREMENT: λn.λf.λx.f(n f x)  - successor function
- DOUBLE:    λn.λf.λx.n f (n f x) - double
- RESET:     λn.λf.λx.x - always return zero (Church 0)
"""
module CounterOps
    using ..BLC

    # Successor: λn.λf.λx.f(nfx)
    const SUCC = Abs(Abs(Abs(App(Var(1), App(App(Var(2), Var(1)), Var(0))))))

    # Add: λm.λn.λf.λx.mf(nfx)
    const ADD = Abs(Abs(Abs(Abs(App(App(Var(3), Var(1)), App(App(Var(2), Var(1)), Var(0)))))))

    # Mult: λm.λn.λf.m(nf)
    const MULT = Abs(Abs(Abs(App(Var(2), App(Var(1), Var(0))))))

    # Zero (reset): λn.λf.λx.x (ignores input, returns Church 0)
    const RESET = Abs(Abs(Abs(Var(0))))

    # Identity (no-op): returns state unchanged
    const NOOP = BLC.I
end

end # module
