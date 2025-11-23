# Debug configuration for PVM execution tracing
# Set these to true/false to enable/disable specific debug outputs

module PVMDebug

# Execution tracing
const TRACE_EXECUTION = false  # Print every instruction step
const TRACE_HOST_CALLS = true  # Print host call invocations
const TRACE_FETCH = false       # Print FETCH host call details
const TRACE_MEMORY = false      # Print memory operations

# Service-level tracing
const TRACE_ACCUMULATE = true   # Print accumulate STF operations

export TRACE_EXECUTION, TRACE_HOST_CALLS, TRACE_FETCH, TRACE_MEMORY, TRACE_ACCUMULATE

end
