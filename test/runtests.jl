using Test
using JAM

@testset "JAM Protocol Tests" begin
    @testset "Blake2b Hash" begin
        # Test hash function
        data = b"test"
        h = JAM.H(data)
        @test length(h) == 32
        @test h != JAM.H0
    end
    
    @testset "Erasure Coding" begin
        enc = JAM.JAMErasure()
        # Create test data of correct size
        data = zeros(UInt8, JAM.DATA_SHARDS * 2)
        encoded = JAM.encode_erasure(enc, data)
        @test length(encoded) == JAM.TOTAL_SHARDS * 2
    end
    
    @testset "Types" begin
        # Test basic type creation
        item = JAM.WorkItem(
            1, JAM.H0, UInt8[], 100, 200,
            Tuple{JAM.Hash, UInt32}[], 
            Tuple{JAM.Hash, UInt32}[], 
            0
        )
        @test item.service == 1
    end
end
