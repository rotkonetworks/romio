#!/usr/bin/env julia
# Extract the blob from test vector to a binary file

using JSON3

data = JSON3.read(read("jam-test-vectors/stf/accumulate/tiny/process_one_immediate_report-1.json", String))

for acc in data[:pre_state][:accounts]
    if acc[:id] == 1729
        for preimage in acc[:data][:preimages_blob]
            if length(preimage[:blob]) > 10000
                blob_hex = preimage[:blob]
                hex_str = blob_hex[3:end]  # Skip "0x"
                blob_bytes = [parse(UInt8, hex_str[i:i+1], base=16) for i in 1:2:length(hex_str)]

                println("Blob length: $(length(blob_bytes)) bytes")
                write("test_blob.polkavm", blob_bytes)
                println("Written to test_blob.polkavm")
                break
            end
        end
        break
    end
end
