#!/usr/bin/env julia
# Simple test running PVM.execute directly

using JSON3
include("src/pvm/pvm.jl")
include("src/pvm/host_calls.jl")
include("src/types/accumulate.jl")

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]
                blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                # Create a minimal context
                # We need a service account for implications
                service_account = ServiceAccount(
                    zeros(UInt8, 32),  # code_hash
                    UInt64(0),  # balance
                    UInt64(0),  # min_acc_gas
                    UInt64(0)   # min_memo_gas
                )
                service_account.items = UInt32(2)  # Start with 2 items as in test

                implications = ImplicationsContext(
                    UInt32(1729),  # service_id
                    service_account,
                    Dict{UInt32, ServiceAccount}(),  # accounts
                    Dict{UInt32, Vector{UInt8}}(),  # privileges
                    UInt32(43)  # current_slot
                )

                context = HostCallContext(
                    implications,
                    zeros(UInt8, 32),  # entropy
                    nothing,  # todo
                    Dict{Symbol, Any}(:results => []),  # work_package
                    nothing   # gas_metadata
                )

                # Entry point 5 for accumulate
                # Input: encode(timeslot, service_id, count) = encode(43, 1729, 1)
                input = UInt8[0x2b, 0x86, 0xc1, 0x01]
                gas = UInt64(100000)

                println("=== EXECUTING PVM ===")
                println("Entry point: 5 (accumulate)")
                println("Input: $(bytes2hex(input))")
                println("Gas: $gas")

                status, output, gas_used, exports = PVM.execute(
                    blob_bytes,
                    input,
                    gas,
                    context,
                    5  # entry point 5
                )

                println("\n=== RESULT ===")
                println("Status: $status")
                println("Output: $(bytes2hex(output))")
                println("Gas used: $gas_used")
                println("Exports: $(length(exports))")
                println()
                println("Implications self items: $(implications.self.items)")
                println("Implications self storage items: $(length(implications.self.storage))")
                println("Implications self last_acc: $(implications.self.last_acc)")
                println("Implications self octets: $(implications.self.octets)")

                break
            end
        end
        break
    end
end
