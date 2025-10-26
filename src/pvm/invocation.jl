# PVM invocation logic for work reports

include("../types/basic.jl")
include("../types/work.jl")
include("../crypto/hash.jl")

# PVM invocation result
struct PvmResult
    success::Bool
    output::Union{Vector{UInt8}, Symbol}  # :out_of_gas, :panic, :bad, :big
    gas_used::Gas
    exports::Dict{Symbol, Any}
end

# invoke PVM for authorization check
function invoke_authorization(
    package::WorkPackage,
    authorizer::Hash,
    state_root::Hash
)::Tuple{Bool, Gas}
    # simplified authorization check
    # in real implementation, would run PVM with auth code

    auth_input = vcat(
        encode(package.authorization_token),
        encode(package.context),
        encode(authorizer)
    )

    # simulate PVM execution
    gas_used = Gas(1000 + length(auth_input))

    # check if authorizer matches expected pattern
    authorized = H(auth_input) == authorizer

    return (authorized, gas_used)
end

# invoke PVM for work item refinement
function invoke_refine(
    item::WorkItem,
    context::WorkContext,
    service::ServiceAccount
)::PvmResult
    # check gas limits
    if item.gas_limit < service.min_gas_limit
        return PvmResult(false, :out_of_gas, item.gas_limit, Dict())
    end

    # simulate PVM execution
    input = vcat(
        encode(item.service),
        encode(item.payload),
        encode(context)
    )

    # simplified execution - would run actual PVM here
    gas_used = Gas(min(item.gas_limit, 5000 + length(input)))

    # generate output based on input hash
    output_hash = H(input)
    output = output_hash[1:min(64, end)]

    # check output size
    if length(output) > item.output_size_limit
        return PvmResult(false, :big, gas_used, Dict())
    end

    return PvmResult(true, output, gas_used, Dict(:result => output))
end

# invoke PVM for accumulation
function invoke_accumulate(
    digest::WorkDigest,
    service::ServiceAccount,
    state_root::Hash
)::PvmResult
    # check if service has enough gas
    if digest.gas_accumulate < service.threshold_gas
        return PvmResult(false, :out_of_gas, 0, Dict())
    end

    # simulate accumulation logic
    if digest.result isa Vector{UInt8}
        # successful result - accumulate
        gas_used = digest.gas_accumulate

        # update service state (simplified)
        new_state = Dict(
            :balance => service.balance,
            :last_accumulation => service.last_accumulation
        )

        return PvmResult(true, digest.result, gas_used, new_state)
    else
        # error result - no accumulation
        return PvmResult(false, digest.result, 0, Dict())
    end
end

# process work report through PVM
function process_work_report(
    report::WorkReport,
    state::State
)::Vector{PvmResult}
    results = PvmResult[]

    for digest in report.digests
        service_id = digest.service

        if haskey(state.services, service_id)
            service = state.services[service_id]
            result = invoke_accumulate(digest, service, state.accumulation_log.root)
            push!(results, result)
        else
            # service doesn't exist
            push!(results, PvmResult(false, :bad, 0, Dict()))
        end
    end

    return results
end

# validate work package prerequisites
function validate_prerequisites(
    package::WorkPackage,
    accumulated::Set{Hash}
)::Bool
    # check all prerequisites are accumulated
    for prereq in package.context.prerequisites
        if prereq ∉ accumulated
            return false
        end
    end
    return true
end

# execute full work package refinement
function execute_work_package(
    package::WorkPackage,
    state::State
)::WorkReport
    # create work report
    digests = WorkDigest[]
    total_gas = Gas(0)

    for item in package.items
        service_id = item.service

        if haskey(state.services, service_id)
            service = state.services[service_id]
            result = invoke_refine(item, package.context, service)

            digest = WorkDigest(
                service = service_id,
                code_hash = service.code_hash,
                payload_hash = H(item.payload),
                gas_accumulate = item.gas_limit,
                result = result.output,
                gas_used = result.gas_used,
                imports_count = 0,
                exports_count = length(result.exports),
                extrinsics_count = 0,
                extrinsics_size = 0
            )

            push!(digests, digest)
            total_gas += result.gas_used
        end
    end

    # create work report
    report = WorkReport(
        specification = package,
        context = package.context,
        core_index = CoreId(0),  # would be assigned by scheduler
        authorizer_hash = H0,
        trace = Vector{UInt8}(),
        segment_roots = Dict{Hash, Hash}(),
        gas_used = total_gas,
        digests = digests
    )

    return report
end

export invoke_authorization, invoke_refine, invoke_accumulate,
       process_work_report, validate_prerequisites, execute_work_package