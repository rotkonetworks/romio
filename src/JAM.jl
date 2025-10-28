# src/JAM.jl
module JAM

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
include("serialization/codec.jl")
include("serialization/complex.jl")
include("serialization/jam_types.jl")
include("serialization/decoder.jl")

# crypto modules
include("crypto/bls.jl")
include("crypto/hash.jl")
include("crypto/erasure.jl")
include("crypto/mmr.jl")

# remaining types
include("types/validator.jl")
include("types/accumulate.jl")
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
