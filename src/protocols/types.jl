include("convenience_functions.jl")

function bytes2int(bytes::Vector{UInt8})
    if length(bytes)==1
        bytes[1]|>Int
    elseif length(bytes)==2
        reinterpret(UInt16, bytes)[1]|>Int
    elseif length(bytes)==3
        reinterpret(UInt32, [bytes;0x00])[1]|>Int
    elseif length(bytes)==4
        reinterpret(UInt32, bytes)[1]|>Int
    elseif length(bytes)==6
        reinterpret(UInt64, [bytes;[0x00, 0x00]])[1]|>Int
    elseif length(bytes)==8
        reinterpret(UInt64, bytes)[1]
    else
        error("Unsupported byte length: $(length(bytes))")
    end
end

function take_lenenc!(packet::Vector{UInt8})
    if packet[1]==0xfc
        bytes=slice!(packet, 3)
        popfirst!(bytes)
        bytes
    elseif packet[1]==0xfd
        bytes=slice!(packet, 4)
        popfirst!(bytes)
        bytes
    elseif packet[1]==0xfe
        bytes=slice!(packet, 9)
        popfirst!(bytes)
        bytes
    else
        slice!(packet, 1)
    end
end

function take_til_nul!(packet::Vector{UInt8})
    nul_position=findfirst(x->x==0x00, packet)
    bytes=slice!(packet, nul_position)
    pop!(bytes)
    bytes
end

function take_til_eof!(packet::Vector{UInt8})
    slice!(packet, length(packet))
end

function int2bytes(num::Number, len, islenenc=false)
    if !islenenc
        if len==1
            num|>UInt8|>collect
        elseif len==2
            num|>
            UInt16|>
            x->reinterpret(UInt8,[x])|>
            collect
        elseif len==3
            bytes=num|>
            UInt32|>
            x->reinterpret(UInt8, [x])|>
            collect
            pop!(bytes)
            bytes
        elseif len==4
            num|>
            UInt32|>
            x->reinterpret(UInt8, [x])|>
            collect
        elseif len==6
            bytes=num|>
            UInt64|>
            x->reinterpret(UInt8, [x])|>
            collect
            pop!(bytes)
            pop!(bytes)
            bytes
        elseif len==8
            num|>
            UInt64|>
            x->reinterpret(UInt8, [x])|>
            collect
        else
            error("Unsupported int<n> type length: $len")
        end
    else
        if len==1
            num|>UInt8|>collect
        elseif len==3
            num|>
            UInt16|>
            x->reinterpret(UInt8, [x])|>
            collect|>
            x->pushfirst!(x, 0xfc)
        elseif len==4
            bytes=num|>
            UInt32|>
            x->reinterpret(UInt8, [x])|>
            collect|>
            x->pushfirst!(x, 0xfd)
            pop!(bytes)
            bytes
        elseif len==9
            num|>
            UInt64|>
            x->reinterpret(UInt8, [x])|>
            collect|>
            x->pushfirst!(x, 0xfe)
        else
            error("Unsupported int<lenenc> type length: $len")
        end
    end
end

function int2lenenc(num)
    if num<251
        int2bytes(num, 1, true)
    elseif num<2^16
        int2bytes(num, 3, true)
    elseif num<2^24
        int2bytes(num, 4, true)
    elseif num<2^64
        int2bytes(num, 9, true)
    else
        error("Unsupported int size: $num")
    end
end

function string2bytes(string, isnullterminated=false)
    if !isnullterminated
        string|>Vector{UInt8}
    else
        string|>Vector{UInt8}|>
        x->push!(x, 0x00)
    end
end



function int_to_flags(num)
    digits(num, base=2, pad=32)
end

function flags_to_int(flags)
    enumerate(flags)|>
    x->map(x) do y
        i, v= y
        v*2^(i-1)
    end|>
    sum
end