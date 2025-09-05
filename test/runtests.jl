using Test
using JAM

@testset "JAM Protocol Tests" begin
    @testset "Blake2b Hash" begin
        data = b"test"
        h = JAM.H(data)
        @test length(h) == 32
        @test h != JAM.H0
    end
    
    @testset "Erasure Coding" begin
        enc = JAM.JAMErasure()
        data = zeros(UInt8, JAM.DS * 2)
        encoded = JAM.encode_erasure(enc, data)
        @test length(encoded) == JAM.V * 2  # Total shards
    end
    
    @testset "Types" begin
        item = JAM.WorkItem(
            1, JAM.H0, UInt8[], 100, 200,
            Tuple{JAM.Hash, UInt32}[], 
            Tuple{JAM.Hash, UInt32}[], 
            0
        )
        @test item.service == 1
    end
end
