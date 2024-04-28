@kwdef mutable struct HandshakeResponse41
    client_flag=0x00000000 | 0x00000002^9
    max_packet_size=0x10000000
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

function HandshakeResponse41(conn::ConnectionHandler, request::HandshakeV10; strict=false)
    response=HandshakeResponse41()
    client_flag=conn.flags
    if strict
        if client_flag!=(client_flag & request.capability_flags)
            error("Error: Client flag contains option(s) unsupported by the server, which is forbidden in strict mode.\n Change the client flag or disable the strict mode.")
        end
    end
    client_flag=client_flag & request.capability_flags
    response.client_flag=client_flag
    response.username=conn.username

    response.database=conn.database

    set_auth!(response, request, conn.password)

    if !is_flag_true(client_flag, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
        response.auth_response_length=(length(response.auth_response))|>UInt8
    end
    response
end

function set_auth!(response, request, password)
    if response.client_plugin_name=="mysql_native_password"
        random_data=vcat(request.auth_plugin_data_part_1, request.auth_plugin_data_part_2[begin:end-1])
        response.auth_response=authenticate_native_password(password, random_data)
    else
        error("Currently unsupported auth plugin: $(response.client_plugin_name)")
    end
end

function render_to_packet(res::HandshakeResponse41)
    packet_components=[
        res.client_flag|>x->int2bytes(x, 4),
        res.max_packet_size|>x->int2bytes(x,4),
        res.character_set|>x->int2bytes(x,1),
        res.filler,
        res.username|>x->string2bytes(x, true),
    ]
    if is_flag_true(res.client_flag, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
        len=length(res.auth_response)
        len_code=lenenc(len)
        push!(packet_components, len_code)
        push!(packet_components, res.auth_response)
    else
        push!(packet_components, res.auth_response_length|>x->int2bytes(x, 1))
        push!(packet_components, res.auth_response)
    end
    if is_flag_true(res.client_flag, CLIENT_CONNECT_WITH_DB)
        push!(packet_components, res.database|>x->string2bytes(x, true))
    end
    if is_flag_true(res.client_flag, CLIENT_PLUGIN_AUTH)
        push!(packet_components, res.client_plugin_name|>x->string2bytes(x, true))
    end
    if is_flag_true(res.client_flag, CLIENT_CONNECT_ATTRS)
    end
    if is_flag_true(res.client_flag, CLIENT_ZSTD_COMPRESSION_ALGORITHM)
    end
    foldl(vcat, packet_components)
end

function lenenc(len)
    if len<251
        int2bytes(len, 1, true)
    elseif len<2^16
        int2bytes(len, 3, true)
    elseif len<2^24
        int2bytes(len, 4, true)
    elseif len<2^64
        int2bytes(len, 9, true)
    else
        error("Unsupported length: Only supports integers lesser than 2^64")
    end
end