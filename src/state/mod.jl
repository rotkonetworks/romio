# State transition module
module StateTransition

export State, state_transition, initial_state

# include all necessary types
include("../types/basic.jl")
include("../types/crypto.jl")
include("../types/work.jl")
include("../types/validator.jl")
include("../types/accumulate.jl")
include("../blocks/header.jl")
include("../blocks/extrinsic.jl")
include("../blocks/block.jl")

# include state components
include("types.jl")
include("state.jl")
include("transition.jl")

# re-export main functions
export state_transition, initial_state, State

end # module