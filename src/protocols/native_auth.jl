function authenticate_native_password_bytes(password, random_data)
    password=Vector{UInt8}(password)
    random_data=Vector{UInt8}(random_data)
    hash1=sha1(password)
    hash2=sha1(hash1)
    hash3=sha1(vcat(random_data, hash2))
    xor.(hash1, hash3)
end

function authenticate_native_password(password, random_data, return_as_hex=false)
    if !return_as_hex
        authenticate_native_password_bytes(password, random_data)
    else
        authenticate_native_password_bytes(password, random_data)|>bytes2hex
    end
end