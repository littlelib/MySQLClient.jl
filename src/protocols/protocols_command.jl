function _test_query()
    vcat([0x03], "show databases;"|>Vector{UInt8})
end

function test_query(conn)
    write(conn, _test_query()|>wrap_packet)
end