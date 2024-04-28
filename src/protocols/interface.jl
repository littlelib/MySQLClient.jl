include("protocol_details/handshakev10.jl")
include("protocol_details/response41.jl")
include("protocol_details/authswitch.jl")

function connect_to_db!(conn::ConnectionHandler)
    result_type, conn=handshake(conn)
    while !isdone(result_type)
        result_type, conn=handshake(conn)
    end
    if iserror(result_type)
        error(render_to_err(conn))
    end
    conn
end

function handshake(conn::ConnectionHandler)
    packet_order, packet_body=unwrap_packet(conn.conn)
    result_type=packet_body[1]
    if result_type==ERROR_PACKET_HEADER
    elseif result_type==0xfe
        packet_body=authswitchrequest(packet_body)|>
        x->authswitchresponse(conn, x)
        t=wrap_packet(packet_body, packet_order)
        write(conn.conn, t)
    elseif result_type==OK_PACKET_HEADER
    elseif result_type==UInt8(10)
        packet_body=handshakev10(packet_body)|>
        x->HandshakeResponse41(conn, x)|>
        render_to_packet
        t=wrap_packet(packet_body, packet_order)
        write(conn.conn, t)
    elseif result_type==0x01
    elseif result_type==0x02
    end
    (result_type, conn)
end

function isdone(result_type::UInt8)
    if result_type==0xff || result_type==0xfe || result_type==0x00
        return true
    else
        return false
    end
end

function iserror(result_type::UInt8)
    if result_type==0xff
        return true
    else
        return false
    end
end