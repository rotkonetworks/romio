# src/JAM.jl
module JAM

# Core includes
include("constants.jl")
include("types/types.jl")
include("crypto/crypto.jl")
include("codec/codec.jl")
include("merkle/merkle.jl")
include("erasure/erasure.jl")
include("pvm/pvm.jl")
include("state/state.jl")
include("blocks/blocks.jl")
include("consensus/safrole.jl")
include("consensus/grandpa.jl")
include("accumulation/accumulation.jl")
include("guarantees/guarantees.jl")
include("audit/audit.jl")

# Main exports
export State, Block, Header
export state_transition, validate_block
export ServiceAccount, WorkPackage, WorkReport

end # module
