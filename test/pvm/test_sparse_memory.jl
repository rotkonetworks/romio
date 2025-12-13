# Unit tests for sparse memory implementation
# Tests single-element access, range access, cross-page operations, and access permissions

include("../../src/pvm/pvm.jl")
using .PVM

function test_single_element_access()
    println("Test 1: Single element read/write")
    mem = PVM.SparseMemoryData()

    # Write single values
    mem[1] = 0x42
    mem[100] = 0xAB
    mem[4096] = 0xCD  # Page boundary
    mem[4097] = 0xEF  # Next page

    # Read back and verify
    @assert mem[1] == 0x42 "Expected 0x42, got $(mem[1])"
    @assert mem[100] == 0xAB "Expected 0xAB, got $(mem[100])"
    @assert mem[4096] == 0xCD "Expected 0xCD at page boundary, got $(mem[4096])"
    @assert mem[4097] == 0xEF "Expected 0xEF at next page, got $(mem[4097])"

    # Unwritten addresses should be 0
    @assert mem[50] == 0x00 "Unwritten address should be 0"
    @assert mem[9999] == 0x00 "Unwritten address should be 0"

    println("  PASS")
end

function test_range_access()
    println("Test 2: Range/slice access")
    mem = PVM.SparseMemoryData()

    # Write a sequence
    for i in 1:10
        mem[i] = UInt8(i * 10)
    end

    # Read as range
    result = mem[1:10]
    @assert length(result) == 10 "Expected length 10, got $(length(result))"
    @assert result == UInt8[10, 20, 30, 40, 50, 60, 70, 80, 90, 100] "Range values don't match"

    # Read partial range
    partial = mem[3:7]
    @assert partial == UInt8[30, 40, 50, 60, 70] "Partial range doesn't match"

    # Read empty range
    empty = mem[5:4]
    @assert length(empty) == 0 "Empty range should have length 0"

    println("  PASS")
end

function test_cross_page_access()
    println("Test 3: Cross-page operations")
    mem = PVM.SparseMemoryData()

    # Write across page boundary (page = 4096 bytes)
    # Page 0: bytes 1-4096, Page 1: bytes 4097-8192
    start_addr = 4090
    for i in 0:20
        mem[start_addr + i] = UInt8((i + 1) % 256)
    end

    # Read across page boundary
    result = mem[start_addr:start_addr+20]
    @assert length(result) == 21 "Cross-page read should return 21 bytes"
    for i in 0:20
        @assert result[i+1] == UInt8((i + 1) % 256) "Cross-page byte $i mismatch"
    end

    println("  PASS")
end

function test_large_address()
    println("Test 4: Large address space (sparse allocation)")
    mem = PVM.SparseMemoryData()

    # Write to widely dispersed addresses (shouldn't allocate all memory between)
    mem[1] = 0x11
    mem[1_000_000] = 0x22  # 1MB offset
    mem[100_000_000] = 0x33  # 100MB offset
    mem[1_000_000_000] = 0x44  # 1GB offset

    # Verify all reads work
    @assert mem[1] == 0x11 "Address 1 should be 0x11"
    @assert mem[1_000_000] == 0x22 "Address 1M should be 0x22"
    @assert mem[100_000_000] == 0x33 "Address 100M should be 0x33"
    @assert mem[1_000_000_000] == 0x44 "Address 1G should be 0x44"

    # Intermediate addresses should be 0
    @assert mem[500_000] == 0x00 "Intermediate should be 0"
    @assert mem[50_000_000] == 0x00 "Intermediate should be 0"

    println("  PASS")
end

function test_access_permissions()
    println("Test 5: Access permissions (SparseAccessData)")
    access = PVM.SparseAccessData()

    # Set permissions
    access[1] = PVM.READ
    access[2] = PVM.WRITE
    access[1000] = PVM.READ

    # Verify permissions
    @assert access[1] == PVM.READ "Page 1 should be READ"
    @assert access[2] == PVM.WRITE "Page 2 should be WRITE"
    @assert access[1000] == PVM.READ "Page 1000 should be READ"
    @assert access[3] === nothing "Unset page should be nothing"
    @assert access[999] === nothing "Unset page should be nothing"

    # Test get() with default
    @assert Base.get(access, 1, :default) == PVM.READ "get() should return READ"
    @assert Base.get(access, 999, :default) == :default "get() should return default"

    println("  PASS")
end

function test_memory_struct()
    println("Test 6: Memory struct integration")
    memory = PVM.Memory()

    # Test data access
    memory.data[100] = 0x42
    @assert memory.data[100] == 0x42 "Memory data access failed"

    # Test range access through Memory struct
    for i in 1:5
        memory.data[i] = UInt8(i)
    end
    result = memory.data[1:5]
    @assert result == UInt8[1, 2, 3, 4, 5] "Memory range access failed"

    # Test access permissions
    memory.access[1] = PVM.WRITE
    @assert memory.access[1] == PVM.WRITE "Memory access permission failed"

    println("  PASS")
end

function test_cache_behavior()
    println("Test 7: Cache optimization (hit same page)")
    mem = PVM.SparseMemoryData()

    # Write several values to same page (should hit cache)
    for i in 1:100
        mem[i] = UInt8(i % 256)
    end

    # Read back (should hit cache)
    for i in 1:100
        @assert mem[i] == UInt8(i % 256) "Cache read mismatch at $i"
    end

    # Access different page, then return (cache miss, then reload)
    mem[5000] = 0xAA
    @assert mem[5000] == 0xAA "Different page write failed"
    @assert mem[50] == UInt8(50) "Return to cached page failed"

    println("  PASS")
end

function test_length()
    println("Test 8: Length compatibility")
    mem = PVM.SparseMemoryData()
    access = PVM.SparseAccessData()

    # Check length methods exist and return expected values
    @assert length(mem) == 1024 * 1024 * 4096 "SparseMemoryData length should be 4GB"
    @assert length(access) == 1024 * 1024 "SparseAccessData length should be 1M pages"

    println("  PASS")
end

# Run all tests
function run_all_tests()
    println("\n=== Sparse Memory Unit Tests ===\n")

    tests = [
        test_single_element_access,
        test_range_access,
        test_cross_page_access,
        test_large_address,
        test_access_permissions,
        test_memory_struct,
        test_cache_behavior,
        test_length,
    ]

    passed = 0
    failed = 0

    for test in tests
        try
            test()
            passed += 1
        catch e
            println("  FAIL: $e")
            failed += 1
        end
    end

    println("\n=== Results ===")
    println("Passed: $passed / $(passed + failed)")
    if failed > 0
        println("FAILED: $failed tests")
        exit(1)
    else
        println("All tests passed!")
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    run_all_tests()
end
