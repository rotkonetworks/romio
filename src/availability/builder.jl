# Work package builder and management

include("../types/basic.jl")
include("../types/work.jl")
include("../types/accumulate.jl")
include("../crypto/hash.jl")
include("erasure.jl")

# Work package builder
mutable struct WorkPackageBuilder
    core_index::CoreId
    current_package::Union{Nothing, WorkPackage}
    pending_items::Vector{WorkItem}
    authorization_pool::Vector{Hash}
    max_package_size::UInt32
    max_items::UInt16
    erasure_engine::ErasureEngine
end

function WorkPackageBuilder(core_index::CoreId)
    WorkPackageBuilder(
        core_index,
        nothing,
        Vector{WorkItem}(),
        Vector{Hash}(),
        1024 * 1024,  # 1MB max package size
        64,            # max 64 items per package
        ErasureEngine()
    )
end

# Work item queue entry
struct QueuedWorkItem
    item::WorkItem
    priority::UInt8
    timestamp::TimeSlot
    authorizer::Hash
end

# Work package scheduler
mutable struct WorkPackageScheduler
    builders::Dict{CoreId, WorkPackageBuilder}
    work_queue::Vector{QueuedWorkItem}
    completed_packages::Vector{Tuple{CoreId, WorkPackage}}
    availability_tracker::AvailabilityTracker
end

function WorkPackageScheduler()
    # Initialize builders for all cores
    builders = Dict{CoreId, WorkPackageBuilder}()
    for core in 1:C
        builders[core] = WorkPackageBuilder(core)
    end

    WorkPackageScheduler(
        builders,
        Vector{QueuedWorkItem}(),
        Vector{Tuple{CoreId, WorkPackage}}(),
        AvailabilityTracker()
    )
end

# Add work item to queue
function add_work_item!(
    scheduler::WorkPackageScheduler,
    item::WorkItem,
    priority::UInt8 = 128,
    authorizer::Hash = H0
)
    queued_item = QueuedWorkItem(
        item,
        priority,
        TimeSlot(time()),
        authorizer
    )

    push!(scheduler.work_queue, queued_item)

    # Sort by priority (lower number = higher priority)
    sort!(scheduler.work_queue, by=qi -> qi.priority)
end

# Build work package for core
function build_work_package!(
    builder::WorkPackageBuilder,
    auth_service::ServiceId,
    auth_code_hash::Hash,
    context::WorkContext,
    available_authorizers::Vector{Hash}
)::Union{WorkPackage, Nothing}

    if isempty(builder.pending_items) || isempty(available_authorizers)
        return nothing
    end

    # Select authorizer
    authorizer = available_authorizers[1]

    # Create authorization token (simplified)
    auth_token = vcat(
        encode(builder.core_index),
        encode(context.anchor),
        authorizer[1:16]  # truncate hash for token
    )

    # Create work package
    package = WorkPackage(
        authorization_token = auth_token,
        auth_service = auth_service,
        auth_code_hash = auth_code_hash,
        auth_config = Vector{UInt8}(),
        context = context,
        items = copy(builder.pending_items)
    )

    # Validate package size
    package_size = length(encode(package))
    if package_size > builder.max_package_size
        # Remove items until it fits
        while !isempty(package.items) && length(encode(package)) > builder.max_package_size
            pop!(package.items)
        end

        if isempty(package.items)
            return nothing
        end
    end

    # Clear pending items that were included
    items_included = length(package.items)
    builder.pending_items = builder.pending_items[items_included+1:end]

    builder.current_package = package
    return package
end

# Schedule work packages for all cores
function schedule_work_packages!(
    scheduler::WorkPackageScheduler,
    state::State,
    current_timeslot::TimeSlot
)::Vector{Tuple{CoreId, WorkPackage}}

    new_packages = Vector{Tuple{CoreId, WorkPackage}}()

    # Distribute work items to cores
    distribute_work_items!(scheduler, state)

    # Build packages for each core
    for (core_id, builder) in scheduler.builders
        if !isempty(builder.pending_items)
            # Get authorization context
            auth_service = ServiceId(1)  # simplified
            auth_code_hash = H0
            context = WorkContext(
                anchor = state.accumulation_log.root,
                state_root = state.accumulation_log.root,
                accumulation_root = state.accumulation_log.root,
                lookup_anchor = H0,
                lookup_slot = current_timeslot,
                prerequisites = Hash[]
            )

            # Get available authorizers for this core
            available_authorizers = state.authorizations[core_id]

            if !isempty(available_authorizers)
                package = build_work_package!(
                    builder,
                    auth_service,
                    auth_code_hash,
                    context,
                    available_authorizers
                )

                if package !== nothing
                    push!(new_packages, (core_id, package))
                    push!(scheduler.completed_packages, (core_id, package))
                end
            end
        end
    end

    return new_packages
end

# Distribute work items to cores based on load balancing
function distribute_work_items!(scheduler::WorkPackageScheduler, state::State)
    # Simple round-robin distribution
    core_loads = Dict{CoreId, Int}()
    for core in 1:C
        core_loads[core] = length(scheduler.builders[core].pending_items)
    end

    # Assign items to least loaded cores
    for queued_item in scheduler.work_queue
        # Find core with minimum load
        min_load = minimum(values(core_loads))
        min_cores = [core for (core, load) in core_loads if load == min_load]

        # Choose first available core
        target_core = min_cores[1]

        # Add item to core
        push!(scheduler.builders[target_core].pending_items, queued_item.item)
        core_loads[target_core] += 1
    end

    # Clear queue
    empty!(scheduler.work_queue)
end

# Encode work package for distribution
function encode_for_distribution(
    scheduler::WorkPackageScheduler,
    core_id::CoreId,
    package::WorkPackage
)::Vector{WorkPackageSegment}
    builder = scheduler.builders[core_id]
    return encode_work_package(builder.erasure_engine, package, core_id)
end

# Process incoming work package segment
function process_segment!(
    scheduler::WorkPackageScheduler,
    segment::WorkPackageSegment
)::Bool
    # Add to availability tracker
    package_available = add_segment!(scheduler.availability_tracker, segment)

    if package_available
        println("Work package $(segment.package_hash) is now available")

        # Try to reconstruct package
        package = reconstruct_package(scheduler.availability_tracker, segment.package_hash)
        if package !== nothing
            println("Successfully reconstructed work package")
            return true
        end
    end

    return false
end

# Get available work packages
function get_available_packages(scheduler::WorkPackageScheduler)::Vector{Hash}
    return collect(scheduler.availability_tracker.complete_packages)
end

# Create work item from service request
function create_work_item(
    service_id::ServiceId,
    payload::Vector{UInt8},
    gas_limit::Gas,
    output_limit::UInt32 = 1024,
    storage_limit::UInt32 = 4096
)::WorkItem
    return WorkItem(
        service = service_id,
        payload = payload,
        gas_limit = gas_limit,
        output_size_limit = output_limit,
        storage_limit = storage_limit
    )
end

# Work package execution context
mutable struct ExecutionContext
    scheduler::WorkPackageScheduler
    current_timeslot::TimeSlot
    state::State
end

function ExecutionContext(state::State)
    ExecutionContext(
        WorkPackageScheduler(),
        state.timeslot,
        state
    )
end

# Execute available work packages
function execute_available_packages!(context::ExecutionContext)::Vector{WorkReport}
    reports = Vector{WorkReport}()
    available_hashes = get_available_packages(context.scheduler)

    for package_hash in available_hashes
        package = reconstruct_package(context.scheduler.availability_tracker, package_hash)

        if package !== nothing
            # Execute package (simplified)
            report = execute_work_package(package, context.state)

            if report !== nothing
                push!(reports, report)
            end
        end
    end

    return reports
end

# Service work submission interface
mutable struct WorkSubmissionInterface
    scheduler::WorkPackageScheduler
    pending_submissions::Vector{Tuple{ServiceId, Vector{UInt8}, Gas}}
end

function WorkSubmissionInterface()
    WorkSubmissionInterface(
        WorkPackageScheduler(),
        Vector{Tuple{ServiceId, Vector{UInt8}, Gas}}()
    )
end

# Submit work for execution
function submit_work!(
    interface::WorkSubmissionInterface,
    service_id::ServiceId,
    payload::Vector{UInt8},
    gas_limit::Gas,
    priority::UInt8 = 128
)::Bool
    # Create work item
    item = create_work_item(service_id, payload, gas_limit)

    # Add to scheduler
    add_work_item!(interface.scheduler, item, priority)

    # Track submission
    push!(interface.pending_submissions, (service_id, payload, gas_limit))

    return true
end

# Process pending submissions
function process_submissions!(
    interface::WorkSubmissionInterface,
    state::State,
    timeslot::TimeSlot
)::Vector{Tuple{CoreId, WorkPackage}}
    # Schedule work packages
    new_packages = schedule_work_packages!(interface.scheduler, state, timeslot)

    # Clear processed submissions
    empty!(interface.pending_submissions)

    return new_packages
end

# Get work package statistics
function get_package_stats(scheduler::WorkPackageScheduler)::Dict{String, Any}
    stats = Dict{String, Any}()

    stats["queued_items"] = length(scheduler.work_queue)
    stats["completed_packages"] = length(scheduler.completed_packages)
    stats["available_packages"] = length(scheduler.availability_tracker.complete_packages)

    # Per-core statistics
    core_stats = Dict{CoreId, Dict{String, Any}}()
    for (core_id, builder) in scheduler.builders
        core_stats[core_id] = Dict{String, Any}(
            "pending_items" => length(builder.pending_items),
            "current_package" => builder.current_package !== nothing
        )
    end
    stats["cores"] = core_stats

    return stats
end

export WorkPackageBuilder, WorkPackageScheduler, QueuedWorkItem,
       ExecutionContext, WorkSubmissionInterface,
       add_work_item!, build_work_package!, schedule_work_packages!,
       encode_for_distribution, process_segment!, submit_work!,
       get_available_packages, get_package_stats, create_work_item