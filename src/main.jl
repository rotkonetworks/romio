# main entry point for JAMit

# include all required modules
include("types/basic.jl")
include("types/crypto.jl")
include("types/work.jl")
include("types/validator.jl")
include("types/accumulate.jl")
include("blocks/header.jl")
include("blocks/extrinsic.jl")
include("blocks/block.jl")
include("crypto/hash.jl")
include("crypto/bls.jl")
include("crypto/erasure.jl")
include("crypto/mmr.jl")
include("state/types.jl")
include("state/state.jl")
include("state/transition.jl")
include("codec/codec.jl")
include("pvm/pvm.jl")

# constants from JAM specification
const C = 341  # number of cores
const V = 1023  # number of validators
const E = 600  # epoch length
const Y = 12  # tail period
const U = 10  # assurance timeout period
const Q = 1023  # authorization queue length
const O = 60  # authorization pool size
const H = 16  # recent history size

# main function to process blocks
function process_block(state::State, block::Block)::State
    return state_transition(state, block)
end

# genesis state initialization
function create_genesis_state()::State
    return initial_state()
end

# validate block against state
function validate_block(state::State, block::Block)::Bool
    # basic validation checks
    if block.header.timeslot <= state.timeslot
        return false
    end

    # check parent hash
    if !isempty(state.recent_blocks)
        if block.header.parent_hash != state.recent_blocks[end].header_hash
            return false
        end
    end

    return true
end

# export main functions
export process_block, create_genesis_state, validate_block