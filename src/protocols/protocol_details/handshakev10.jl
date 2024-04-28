@kwdef mutable struct HandshakeV10
    protocol_version=nothing
    server_version=nothing
    thread_id=nothing
    auth_plugin_data_part_1=nothing
    filler=nothing
    capability_flags_1=nothing
    character_set=nothing
    status_flags=nothing
    capability_flags_2=nothing
    auth_plugin_data_len=nothing
    _00=nothing
    reserved=nothing
    auth_plugin_data_part_2=nothing
    auth_plugin_name=nothing
    capability_flags=nothing
end

function handshakev10(conn::ConnectionHandler)

end

function handshakev10(packet_body::Vector)
    result=HandshakeV10()
    result.protocol_version=slice!(packet_body, 1)
    result.server_version=take_til_nul!(packet_body)
    result.thread_id=slice!(packet_body, 4)
    result.auth_plugin_data_part_1=slice!(packet_body, 8)
    result.filler=slice!(packet_body, 1)
    result.capability_flags_1=slice!(packet_body, 2)
    result.character_set=slice!(packet_body, 1)
    result.status_flags=slice!(packet_body, 2)
    result.capability_flags_2=slice!(packet_body, 2)
    if is_flag_true!(result, CLIENT_PLUGIN_AUTH)
        result.auth_plugin_data_len=slice!(packet_body, 1)
    else
        result._00=slice!(packet_body, 1)
    end
    result.reserved=slice!(packet_body, 10)
    result.auth_plugin_data_part_2=slice!(packet_body, auth_length(result))
    if is_flag_true!(result, CLIENT_PLUGIN_AUTH)
        result.auth_plugin_name=take_til_nul!(packet_body)
    end
    result
end

function is_flag_true!(result::HandshakeV10, index)
    if isnothing(result.capability_flags)
        capability_flags=vcat(result.capability_flags_1, result.capability_flags_2)|>
        bytes2int
        result.capability_flags=capability_flags
    end
    (result.capability_flags & 0x00000002^index)!=0
end

function is_flag_true(flag::Integer, index)
    flag=UInt32(flag)
    (flag & 0x00000002^index)!=0
end

function auth_length(result)
    if isnothing(result.auth_plugin_data_len)
        13
    else
        max(13, (result.auth_plugin_data_len[1]|>Int)-8)
    end
end

