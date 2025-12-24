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

# pvm interpreter
include("pvm/pvm.jl")
include("pvm/polkavm_blob.jl")
include("pvm/corevm_extension.jl")

# exports
export State, Block, Header
export ServiceAccount, WorkPackage, WorkReport
export H, H0, Hash, JAMErasure

# Export codec functions
export Codec, ComplexCodec, JAMCodec, Decoder

# CLI entry point for PackageCompiler
Base.@ccallable function julia_main()::Cint
    try
        # Find the project directory
        # When compiled: executable is in <app>/bin/, project in <app>/share/julia/
        exe_path = Base.julia_cmd().exec[1]
        app_dir = dirname(dirname(exe_path))

        if isfile(joinpath(app_dir, "share", "julia", "Project.toml"))
            project_dir = joinpath(app_dir, "share", "julia")
        else
            # Development mode - use source tree
            project_dir = dirname(dirname(@__FILE__))
        end

        # Include and run the CLI
        include(joinpath(project_dir, "bin", "romio"))
        return 0
    catch e
        if e isa InterruptException
            return 130
        end
        showerror(stderr, e, catch_backtrace())
        return 1
    end
end

end # module JAM
