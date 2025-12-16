# STF Module - State Transition Functions
# Provides precompilable STF implementations

module STF

using JSON3
using StaticArrays

# Export all STF functions
export process_safrole, run_safrole_test_vector
export process_disputes, run_disputes_test_vector
export process_reports, run_reports_test_vector
export process_assurances, run_assurances_test_vector
export process_accumulate, run_accumulate_test_vector
export process_preimages, run_preimages_test_vector
export process_statistics, run_statistics_test_vector
export process_history, run_history_test_vector
export process_authorizations, run_authorizations_test_vector

# Include shared dependencies once
include("../types/basic.jl")
include("../types/accumulate.jl")
include("../test_vectors/loader.jl")
include("../test_vectors/comparison.jl")
include("../crypto/Blake2b.jl")
include("../crypto/ed25519.jl")
include("../crypto/bandersnatch.jl")
include("../encoding/jam.jl")
include("../pvm/pvm.jl")
using .PVM

# Include STF implementations (without their include statements)
# We need to create "core" versions that don't re-include dependencies

# Inline the core STF logic here to avoid include overhead
# For now, just include the files - this gives module precompilation benefits

# Statistics - simple, no heavy deps
include("statistics_core.jl")

# History - simple
include("history_core.jl")

# Authorizations - simple
include("authorizations_core.jl")

# Safrole - uses bandersnatch
include("safrole_core.jl")

# Assurances - uses ed25519
include("assurances_core.jl")

# Disputes - uses ed25519
include("disputes_core.jl")

# Reports - uses ed25519
include("reports_core.jl")

# Preimages - uses Blake2b
include("preimages_core.jl")

# Accumulate - uses PVM (heaviest)
include("accumulate_core.jl")

end # module STF
