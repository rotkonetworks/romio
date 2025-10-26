# Complete JAM validator node implementation

include("../state/state.jl")
include("../state/transition.jl")
include("../consensus/safrole.jl")
include("../consensus/production.jl")
include("../consensus/grandpa.jl")
include("../consensus/best_chain.jl")
include("../availability/erasure.jl")
include("../availability/builder.jl")
include("../pvm/engine.jl")
include("../pvm/invocation.jl")

# Validator node configuration
struct ValidatorConfig
    validator_key::ValidatorKey
    is_authority::Bool  # whether this node can produce blocks
    enable_grandpa::Bool
    enable_work_processing::Bool
    data_directory::String
    network_port::UInt16
    max_work_items::UInt32
    gas_limit_per_block::Gas
end

function ValidatorConfig(validator_key::ValidatorKey)
    ValidatorConfig(
        validator_key,
        true,
        true,
        true,
        "./jam_data",
        30333,
        1000,
        Gas(10_000_000)
    )
end

# Validator node state
mutable struct ValidatorNode
    config::ValidatorConfig
    state::State
    block_producer::Union{Nothing, BlockProducer}
    grandpa_service::Union{Nothing, GrandpaService}
    best_chain_service::BestChainService
    work_scheduler::WorkPackageScheduler
    work_interface::WorkSubmissionInterface
    availability_tracker::AvailabilityTracker

    # Runtime state
    running::Bool
    current_timeslot::TimeSlot
    last_tick::Float64

    # Performance metrics
    blocks_produced::UInt32
    blocks_imported::UInt32
    packages_processed::UInt32
    segments_received::UInt32
end

# Initialize validator node
function ValidatorNode(config::ValidatorConfig, genesis_state::State)
    # Initialize services
    best_chain_service = BestChainService(H0)  # genesis hash

    grandpa_service = if config.enable_grandpa
        GrandpaService(genesis_state.current_validators, H0, config.validator_key)
    else
        nothing
    end

    block_producer = if config.is_authority
        BlockProducer(config.validator_key, genesis_state)
    else
        nothing
    end

    node = ValidatorNode(
        config,
        deepcopy(genesis_state),
        block_producer,
        grandpa_service,
        best_chain_service,
        WorkPackageScheduler(),
        WorkSubmissionInterface(),
        AvailabilityTracker(),
        false,  # not running initially
        genesis_state.timeslot,
        time(),
        0, 0, 0, 0  # metrics
    )

    # Connect services
    if grandpa_service !== nothing
        set_grandpa!(best_chain_service, grandpa_service)
    end

    return node
end

# Start validator node
function start_node!(node::ValidatorNode)
    node.running = true
    node.last_tick = time()

    # Start services
    start_best_chain!(node.best_chain_service)

    if node.grandpa_service !== nothing
        start_grandpa!(node.grandpa_service)
    end

    if node.block_producer !== nothing
        start_production!(node.block_producer)
    end

    println("JAM Validator Node started")
    println("Authority: $(node.config.is_authority)")
    println("GRANDPA: $(node.config.enable_grandpa)")
    println("Work Processing: $(node.config.enable_work_processing)")
    println("Validator Key: $(node.config.validator_key.ed25519)")
end

# Stop validator node
function stop_node!(node::ValidatorNode)
    node.running = false

    # Stop services
    stop_best_chain!(node.best_chain_service)

    if node.grandpa_service !== nothing
        stop_grandpa!(node.grandpa_service)
    end

    if node.block_producer !== nothing
        stop_production!(node.block_producer)
    end

    println("JAM Validator Node stopped")
end

# Main node tick - called regularly to process events
function node_tick!(node::ValidatorNode)
    if !node.running
        return
    end

    current_time = time()

    # Update timeslot
    jam_epoch_start = 1735732800.0  # JAM Common Era
    seconds_since_epoch = current_time - jam_epoch_start
    current_timeslot = max(1, floor(Int, seconds_since_epoch / 6.0))
    node.current_timeslot = current_timeslot

    # Tick services
    best_chain_tick!(node.best_chain_service)

    if node.grandpa_service !== nothing
        (best_hash, best_number) = get_best_block(node.best_chain_service)
        grandpa_tick!(node.grandpa_service, best_hash, best_number)
    end

    # Block production
    if node.block_producer !== nothing
        produced_block = production_tick!(node.block_producer)
        if produced_block !== nothing
            process_new_block!(node, produced_block, true)  # our own block
            node.blocks_produced += 1
        end
    end

    # Work package processing
    if node.config.enable_work_processing
        process_work_packages!(node)
    end

    # Update metrics
    node.last_tick = current_time
end

# Process new block
function process_new_block!(node::ValidatorNode, block::Block, is_own::Bool = false)
    # Validate block
    valid, msg = validate_block(node.state, block)
    if !valid
        println("Invalid block received: $msg")
        return false
    end

    # Apply state transition
    new_state = state_transition(node.state, block)

    # Update node state
    node.state = new_state
    node.current_timeslot = new_state.timeslot

    # Add to best chain tracker
    block_hash = H(encode(block.header))
    add_block!(node.best_chain_service.tracker, block, new_state, true)

    # Update metrics
    if !is_own
        node.blocks_imported += 1
    end

    # Process work packages in block
    for guarantee in block.extrinsic.guarantees.guarantees
        # Extract work package segments (would be received via network)
        segments = encode_for_distribution(node.work_scheduler, guarantee.report.core_index, guarantee.report.specification)

        # Process first few segments to simulate network reception
        for segment in segments[1:min(3, length(segments))]
            process_segment!(node.work_scheduler, segment)
            node.segments_received += 1
        end
    end

    println("Processed block at timeslot $(block.header.timeslot)")
    return true
end

# Process work packages
function process_work_packages!(node::ValidatorNode)
    # Process pending work submissions
    new_packages = process_submissions!(node.work_interface, node.state, node.current_timeslot)

    for (core_id, package) in new_packages
        println("Scheduled work package for core $core_id")
        node.packages_processed += 1
    end

    # Execute available packages
    execution_context = ExecutionContext(node.state)
    execution_context.current_timeslot = node.current_timeslot
    execution_context.scheduler = node.work_scheduler

    reports = execute_available_packages!(execution_context)

    for report in reports
        println("Executed work package with $(length(report.digests)) items")
    end
end

# Submit work to node
function submit_work!(
    node::ValidatorNode,
    service_id::ServiceId,
    payload::Vector{UInt8},
    gas_limit::Gas,
    priority::UInt8 = 128
)::Bool
    if !node.config.enable_work_processing
        return false
    end

    return submit_work!(node.work_interface, service_id, payload, gas_limit, priority)
end

# Get node status
function get_node_status(node::ValidatorNode)::Dict{String, Any}
    status = Dict{String, Any}()

    # Basic info
    status["running"] = node.running
    status["timeslot"] = node.current_timeslot
    status["authority"] = node.config.is_authority

    # State info
    status["state"] = Dict{String, Any}(
        "timeslot" => node.state.timeslot,
        "validators" => length(node.state.current_validators),
        "services" => length(node.state.services),
        "pending_reports" => count(r -> r !== nothing, node.state.pending_reports)
    )

    # Chain info
    (best_hash, best_number) = get_best_block(node.best_chain_service)
    (fin_hash, fin_number) = get_finalized_block(node.best_chain_service)

    status["chain"] = Dict{String, Any}(
        "best_block" => best_number,
        "finalized_block" => fin_number,
        "best_hash" => best_hash,
        "finalized_hash" => fin_hash
    )

    # Metrics
    status["metrics"] = Dict{String, Any}(
        "blocks_produced" => node.blocks_produced,
        "blocks_imported" => node.blocks_imported,
        "packages_processed" => node.packages_processed,
        "segments_received" => node.segments_received
    )

    # Work package stats
    status["work"] = get_package_stats(node.work_scheduler)

    return status
end

# Handle incoming GRANDPA vote
function handle_grandpa_vote!(node::ValidatorNode, vote::GrandpaVote)::Bool
    if node.grandpa_service === nothing
        return false
    end

    return add_vote!(node.grandpa_service, vote)
end

# Handle incoming work package segment
function handle_work_segment!(node::ValidatorNode, segment::WorkPackageSegment)::Bool
    success = process_segment!(node.work_scheduler, segment)
    if success
        node.segments_received += 1
    end
    return success
end

# Get pending work packages for distribution
function get_pending_packages(node::ValidatorNode)::Vector{Tuple{CoreId, WorkPackage}}
    return node.work_scheduler.completed_packages
end

# Validator node manager for running multiple nodes
mutable struct ValidatorManager
    nodes::Dict{Ed25519Key, ValidatorNode}
    genesis_state::State
    running::Bool
    tick_interval::Float64
end

function ValidatorManager(genesis_state::State)
    ValidatorManager(
        Dict{Ed25519Key, ValidatorNode}(),
        genesis_state,
        false,
        1.0  # 1 second tick interval
    )
end

# Add validator to manager
function add_validator!(
    manager::ValidatorManager,
    config::ValidatorConfig
)::ValidatorNode
    node = ValidatorNode(config, manager.genesis_state)
    manager.nodes[config.validator_key.ed25519] = node

    if manager.running
        start_node!(node)
    end

    return node
end

# Start all validators
function start_validators!(manager::ValidatorManager)
    manager.running = true

    for (_, node) in manager.nodes
        start_node!(node)
    end

    println("Started $(length(manager.nodes)) validator nodes")
end

# Stop all validators
function stop_validators!(manager::ValidatorManager)
    manager.running = false

    for (_, node) in manager.nodes
        stop_node!(node)
    end

    println("Stopped all validator nodes")
end

# Tick all validators
function tick_all_validators!(manager::ValidatorManager)
    if !manager.running
        return
    end

    for (_, node) in manager.nodes
        node_tick!(node)
    end
end

# Run validator manager (blocking)
function run_validator_manager!(manager::ValidatorManager)
    start_validators!(manager)

    try
        while manager.running
            tick_all_validators!(manager)
            sleep(manager.tick_interval)
        end
    catch InterruptException
        println("Interrupted, stopping validators...")
    finally
        stop_validators!(manager)
    end
end

# Get all node statuses
function get_all_status(manager::ValidatorManager)::Dict{String, Any}
    statuses = Dict{String, Any}()

    for (key, node) in manager.nodes
        statuses[string(key)] = get_node_status(node)
    end

    return statuses
end

export ValidatorConfig, ValidatorNode, ValidatorManager,
       start_node!, stop_node!, node_tick!, process_new_block!,
       submit_work!, get_node_status, handle_grandpa_vote!,
       handle_work_segment!, add_validator!, run_validator_manager!