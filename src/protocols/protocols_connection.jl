"""Protocol::HandshakeV10"""

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

function handshakev10(packet_body)
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
    if isauth!(result, CLIENT_PLUGIN_AUTH)
        result.auth_plugin_data_len=slice!(packet_body, 1)
    else
        result._00=slice!(packet_body, 1)
    end
    result.reserved=slice!(packet_body, 10)
    result.auth_plugin_data_part_2=slice!(packet_body, auth_length(result))
    if isauth_stored(result, CLIENT_PLUGIN_AUTH)
        result.auth_plugin_name=take_til_nul!(packet_body)
    end
    result
end

function isauth!(result, index)
    capability_flags=vcat(result.capability_flags_1, result.capability_flags_2)|>
    bytes2int
    println(capability_flags)
    result.capability_flags=capability_flags
    (capability_flags & 0x02^index)!=0
end

function auth_length(result)
    if isnothing(result.auth_plugin_data_len)
        13
    else
        max(13, (result.auth_plugin_data_len[1]|>Int)-8)
    end
end

function isauth_stored(result, index)
    (result.capability_flags & 0x02^index)!=0
end





"""Protocol::HandshakeResponse41"""
default_flags=zeros(Int, 32)|>
x->begin
    for i in [CLIENT_PROTOCOL_41, CLIENT_PLUGIN_AUTH, CLIENT_CONNECT_WITH_DB]
    x[i]=1
    end
    x
end|>
flags_to_int|>
x->int2bytes(x, 4)

@kwdef mutable struct HandshakeResponse41
    client_flag=default_flags
    max_packet_size=0xFFFFFFFF
    character_set=0x21
    filler=zeros(UInt8, 23)
    username=nothing
    auth_response=nothing
    auth_response_length=nothing
    database=nothing
    client_plugin_name="mysql_native_password"
    length_key_values=nothing
    key_1=nothing
    value_1=nothing
    zstd_compression_level=nothing
end

function handshake_response_41(conn, req, username, password, dbname=nothing;params...)
    packet_body=_handshake_response_41(req, username, password, dbname; params...)
    packet=wrap_packet(packet_body, 0)
    write(conn, packet)
end

function _handshake_response_41(req, username, password, dbname=nothing; params...)
    res=HandshakeResponse41()
    for (s,v) in params
        setfield!(res, s, v)
    end
    res.username=username
    res.database=dbname
    set_auth!(res, req, password)
    res|>render_to_packet|>println
    res|>render_to_packet
end

function set_auth!(res, req, password)
    if res.client_plugin_name=="mysql_native_password"
        random_data=vcat(req.auth_plugin_data_part_1, req.auth_plugin_data_part_2[begin:end-1])
        res.auth_response=authenticate_native_password(password, random_data)
    else
        error("Not yet supported auth plugin: $res.client_plugin_name")
    end
end

function render_to_packet(res::HandshakeResponse41)
    packet_components=[
        res.client_flag,
        res.max_packet_size|>
        x->int2bytes(x, 4),
        res.character_set|>
        x->int2bytes(x, 1),
        res.filler,
        res.username|>x->string2bytes(x, true)
    ]
    if isnothing(res.auth_response_length)
        push!(packet_components, res.auth_response)
        push!(packet_components, 0x00|>collect)
    else
        push!(packet_components, res.auth_response_length|>x->int2bytes(x, 1))
        push!(packet_components, res.auth_response)
        push!(packet_components, 0x00|>collect)
    end
    if !isnothing(res.database)
        push!(packet_components, res.database|>x->string2bytes(x, true))
    end
    if !isnothing(res.client_plugin_name)
        push!(packet_components, res.client_plugin_name|>x->string2bytes(x, true))
    end
    #=
    if !isnothing(res.length_key_values)
        push!(packet_components, res.length_key_values|>int2lenenc)
        push!(packet)
        =#
    if !isnothing(res.zstd_compression_level)
        push!(packet_components, res.zstd_compression_level|>x->int2bytes(x, 1))
    end
    foldl(vcat, packet_components)
end


function auth_switch_request(conn, password)
    packet_order, packet_body=unwrap_packet(conn)
    status_tag=slice!(packet_body,1)|>pop!
    if status_tag==0xfe
        plugin_name=take_til_nul!(packet_body)|>String
        plugin_provided_data=packet_body|>take_til_nul!
        authenticate_native_password(password, plugin_provided_data)|>
        x->wrap_packet(x, packet_order)|>
        x->write(conn, x)
    else
        error("unexpected status tag $status_tag: expected 0xFE")
    end
end
