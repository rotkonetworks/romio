module JAM

using Blake2
using BinaryFields
using BinaryReedSolomon
using BatchedMerkleTree
using StaticArrays
using DataStructures

# constants
include("constants.jl")

# types in dependency order
include("types/basic.jl")
include("crypto/hash.jl")
include("types/validator.jl")
include("types/service.jl")
include("types/work.jl")

# crypto
include("crypto/erasure.jl")
include("crypto/mmr.jl")
include("crypto/bls.jl")

# state
include("state/state.jl")

# blocks
include("blocks/header.jl")
include("blocks/extrinsic.jl")
include("blocks/blocks.jl")

# state transition
include("state/transition.jl")

# exports
export State, Block, Header
export ServiceAccount, WorkPackage, WorkReport
export H, H0, Hash, JAMErasure

end # module JAM
