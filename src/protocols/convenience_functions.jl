
"""Vector related functions"""
function slice!(vec, index)
    vec_to_return=splice!(vec, firstindex(vec):(firstindex(vec)+index-1))
    return vec_to_return
end

function remove_first_line(string)
    split(string, "\n", limit=2)|>pop!
end


"""Protocol related functions"""
function unwrap_packet(conn)
    packet_length=read(conn, 3)|>
    bytes2int
    packet_order=read(conn, 1)|>pop!|>Int
    packet_body=read(conn, packet_length)
    (packet_order, packet_body)
end

function wrap_packet(packet_body, previous_count=-1)
    packet_length=length(packet_body)|>
    x->int2bytes(x, 3)
    count=(previous_count+1)|>UInt8|>collect
    foldl(vcat, [packet_length, count, packet_body])
end


function include_from_dir(dirpath)
    paths=readdir(dirpath, join=true)
    for path in paths
        if isfile(path)
            if contains(path, r".\.jl$")
                include(path)
                println("included: $path")
            end
        end
    end
end