@kwdef mutable struct ClientFlags
    CLIENT_LONG_PASSWORD::Bool=false
    CLIENT_FOUND_ROWS::Bool=false
    CLIENT_LONG_FLAG::Bool=false
    CLIENT_CONNECT_WITH_DB::Bool=false
    CLIENT_NO_SCHEMA::Bool=false
    CLIENT_COMPRESS::Bool=false
    CLIENT_ODBC::Bool=false
    CLIENT_LOCAL_FILES::Bool=false
    CLIENT_IGNORE_SPACE::Bool=false
    CLIENT_PROTOCOL_41::Bool=true
    CLIENT_INTERACTIVE::Bool=false
    CLIENT_SSL::Bool=false
    CLIENT_IGNORE_SIGPIPE::Bool=false
    CLIENT_TRANSACTIONS::Bool=false
    CLIENT_RESERVED::Bool=false
    CLIENT_RESERVED2::Bool=false
    CLIENT_MULTI_STATEMENTS::Bool=false
    CLIENT_MULTI_RESULTS::Bool=false
    CLIENT_PS_MULTI_RESULTS::Bool=false
    CLIENT_PLUGIN_AUTH::Bool=false
    CLIENT_CONNECT_ATTRS::Bool=false
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA::Bool=false
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS::Bool=false
    CLIENT_SESSION_TRACK::Bool=false
    CLIENT_DEPRECATE_EOF::Bool=false
    CLIENT_OPTIONAL_RESULTSET_METADATA::Bool=false
    CLIENT_ZSTD_COMPRESSION_ALGORITHM::Bool=false
    CLIENT_QUERY_ATTRIBUTES::Bool=false
    MULTI_FACTOR_AUTHENTICATION::Bool=false
    CLIENT_CAPABILITY_EXTENSION::Bool=false
    CLIENT_SSL_VERIFY_SERVER_CERT::Bool=false
    CLIENT_REMEMBER_OPTIONS::Bool=false
end


default_flags=ClientFlags()
default_options=Dict()
default_options[:protocol41]=true
default_options[:client_plugin_auth]=true

"""
options
ssl

"""

@kwdef mutable struct ConnectionHandler
    username::Union{String, Nothing}=nothing
    password::Union{String, Nothing}=nothing
    database::Union{String, Nothing}=nothing
    conn=nothing
    flags::UInt32=UInt32(0)
    options::Dict{Any, Any}=default_options
    result=nothing
end

function ConnectionHandler(address::Union{String, IPAddr}, port::Int)
    tcp_conn=connect(address, port)
    ConnectionHandler(conn=tcp_conn)
end



function set_flags!(conn::ConnectionHandler)
    if !isnothing(conn.database)
        set_flag!(conn, CLIENT_CONNECT_WITH_DB, true)
    end
    for (k,v) in conn.options
        get(options_to_flags, k) do
            (x,y)->nothing
        end(conn, v)
    end
end

options_to_flags=Dict()

function set_flag!(conn::ConnectionHandler, flag, is_on::Bool=true)
    if is_on
        conn.flags=conn.flags | 0x00000002^flag
    else
        conn.flags=conn.flags & ~0x00000002^flag
    end
end

options_to_flags[:ssl]=(conn, v)->begin
    set_flag!(conn, CLIENT_SSL, v)
end
options_to_flags[:protocol41]=(conn, v)->begin
    set_flag!(conn, CLIENT_PROTOCOL_41, v)
end
options_to_flags[:client_plugin_auth]=(conn, v)->begin
    set_flag!(conn, CLIENT_PLUGIN_AUTH, v)
end

function get_flags(conn::ConnectionHandler)
    conn.flags
end



"""
ConnectionHandler()|>
handshakev10|>#(conn, result, sequence)
handshake_response_41
"""