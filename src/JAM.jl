# src/JAM.jl
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

# codec modules
include("codec/codec.jl")
include("codec/complex.jl")
include("codec/jam_types.jl")
include("codec/decoder.jl")

# crypto modules
include("crypto/bls.jl")
include("crypto/hash.jl")
include("crypto/erasure.jl")
include("crypto/mmr.jl")

# remaining types
include("types/validator.jl")
include("types/service.jl")
include("types/work.jl")

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

# Export codec functions
export Codec, ComplexCodec, JAMCodec, Decoder

end # module JAM
