function authswitchrequest(packet_body)
    (status_flag=slice!(packet_body,1), plugin_name=take_til_nul!(packet_body), plugin_provided_data=take_til_eof!(packet_body))
end

function authswitchresponse(conn::ConnectionHandler, request)
    if request.plugin_name=="mysql_native_password"|>string2bytes
        authenticate_native_password(conn.password, request.plugin_provided_data[begin:end-1])
    else
        error("Not yet implemented")
    end
end