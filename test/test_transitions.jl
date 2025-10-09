# test state transitions
using Test

# include main module
include("../src/main.jl")

@testset "State Transitions" begin

    @testset "Initial State" begin
        state = create_genesis_state()
        @test state.timeslot == 0
        @test length(state.current_validators) == 0
        @test length(state.pending_reports) == C
        @test all(r -> r === nothing, state.pending_reports)
    end

    @testset "Empty Block Transition" begin
        state = create_genesis_state()

        # create minimal block
        header = Header(
            parent_hash = H0,
            parent_state_root = H0,
            extrinsics_hash = H0,
            timeslot = 1,
            epoch_marker = nothing,
            tickets_marker = nothing,
            seal = zeros(64),
            author = zeros(32),
            vrf_signature = BandersnatchSig(zeros(96))
        )

        extrinsic = Extrinsic(
            tickets = TicketExtrinsic([]),
            preimages = PreimageExtrinsic([]),
            guarantees = GuaranteeExtrinsic([]),
            assurances = AssuranceExtrinsic([]),
            disputes = DisputeExtrinsic([], [], [])
        )

        block = Block(header, extrinsic)

        # process block
        new_state = process_block(state, block)

        @test new_state.timeslot == 1
        @test length(new_state.recent_blocks) == 1
    end

    @testset "Entropy Update" begin
        state = create_genesis_state()
        state.entropy = (H0, H0, H0, H0)

        header = Header(
            parent_hash = H0,
            parent_state_root = H0,
            extrinsics_hash = H0,
            timeslot = 1,
            epoch_marker = nothing,
            tickets_marker = nothing,
            seal = zeros(64),
            author = zeros(32),
            vrf_signature = BandersnatchSig(rand(UInt8, 96))
        )

        extrinsic = Extrinsic(
            tickets = TicketExtrinsic([]),
            preimages = PreimageExtrinsic([]),
            guarantees = GuaranteeExtrinsic([]),
            assurances = AssuranceExtrinsic([]),
            disputes = DisputeExtrinsic([], [], [])
        )

        block = Block(header, extrinsic)
        new_state = process_block(state, block)

        # entropy should have changed
        @test new_state.entropy[1] != state.entropy[1]
    end

    @testset "Dispute Processing" begin
        state = create_genesis_state()

        # add some validators
        push!(state.current_validators, ValidatorKey(
            BandersnatchKey(zeros(32)),
            Ed25519Key(ones(32)),
            BlsKey(zeros(144))
        ))

        verdict = Verdict(
            report_hash = H(rand(UInt8, 32)),
            epoch = 0,
            judgments = [(false, 1, Ed25519Sig(zeros(64)))]
        )

        disputes = DisputeExtrinsic([verdict], [], [])

        header = Header(
            parent_hash = H0,
            parent_state_root = H0,
            extrinsics_hash = H0,
            timeslot = 1,
            epoch_marker = nothing,
            tickets_marker = nothing,
            seal = zeros(64),
            author = zeros(32),
            vrf_signature = BandersnatchSig(zeros(96))
        )

        extrinsic = Extrinsic(
            tickets = TicketExtrinsic([]),
            preimages = PreimageExtrinsic([]),
            guarantees = GuaranteeExtrinsic([]),
            assurances = AssuranceExtrinsic([]),
            disputes = disputes
        )

        block = Block(header, extrinsic)
        new_state = process_block(state, block)

        # check that offender was marked
        @test length(new_state.judgments.offenders) == 1
        @test length(new_state.judgments.punish_set) == 1
        @test length(new_state.judgments.bad_reports) == 1
    end

    @testset "Preimage Integration" begin
        state = create_genesis_state()

        # add a service
        service_id = ServiceId(1)
        state.services[service_id] = ServiceAccount(
            storage = Dict{Blob, Blob}(),
            preimages = Dict{Hash, Blob}(),
            preimage_meta = Dict{Tuple{Hash, UInt32}, Vector{TimeSlot}}(),
            code_hash = H0,
            balance = Balance(1000),
            threshold_gas = Gas(100),
            min_gas_limit = Gas(10),
            last_accumulation = TimeSlot(0),
            preimage_requests = Set{Hash}()
        )

        preimage_data = Vector{UInt8}(b"test preimage data")
        preimages = PreimageExtrinsic([(service_id, preimage_data)])

        header = Header(
            parent_hash = H0,
            parent_state_root = H0,
            extrinsics_hash = H0,
            timeslot = 1,
            epoch_marker = nothing,
            tickets_marker = nothing,
            seal = zeros(64),
            author = zeros(32),
            vrf_signature = BandersnatchSig(zeros(96))
        )

        extrinsic = Extrinsic(
            tickets = TicketExtrinsic([]),
            preimages = preimages,
            guarantees = GuaranteeExtrinsic([]),
            assurances = AssuranceExtrinsic([]),
            disputes = DisputeExtrinsic([], [], [])
        )

        block = Block(header, extrinsic)
        new_state = process_block(state, block)

        # check preimage was stored
        preimage_hash = H(preimage_data)
        @test haskey(new_state.services[service_id].preimages, preimage_hash)
        @test new_state.services[service_id].preimages[preimage_hash] == preimage_data
    end
end

println("Running state transition tests...")
@time @testset "All Tests" begin
    include("test_transitions.jl")
end