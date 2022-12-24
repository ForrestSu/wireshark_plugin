-- @brief  Wireshark plugin for tRPC Protocol
-- @date   2022.12.24
-- @doc    https://wiki.wireshark.org/LuaAPI

local VersionText = {
    [0x0] = "V0",
    [0x1] = "V1",
}

local FrameTypeText = {
    [0x0] = "UNARY_FRAME",  -- 一应一答模式的二进制数据帧类型
    [0x1] = "STREAM_FRAME", -- 流式模式的二进制数据帧类型
}

local StreamFrameTypeText = {
    [0x0] = "UNARY",
    [0x1] = "INIT",
    [0x2] = "DATA",
    [0x3] = "FEEDBACK",
    [0x4] = "CLOSE",
}

-- 1. Create Protocol Object
local NAME = "tRPC"
local trpcProto = Proto(NAME, "TRPC Protocol")

-- 2. Define Protocol Fields
local fields = trpcProto.fields
fields.Magic = ProtoField.uint16(NAME .. ".Magic", "Magic", base.HEX)
fields.FrameType = ProtoField.uint8(NAME .. ".FrameType", "FrameType", base.DEC, FrameTypeText)
fields.StreamFrameType = ProtoField.uint8(NAME .. ".StreamFrameType", "StreamFrameType", base.DEC, StreamFrameTypeText)
fields.TotalLen = ProtoField.uint32(NAME .. ".TotalLen", "TotalLen", base.DEC)
fields.HeaderLen = ProtoField.uint16(NAME .. ".HeaderLen", "HeaderLen", base.DEC)
fields.StreamID = ProtoField.uint32(NAME .. ".StreamID", "StreamID", base.DEC)
fields.Version = ProtoField.uint8(NAME .. ".Version", "Version", base.DEC, VersionText)
fields.Reserved = ProtoField.uint8(NAME .. ".Reserved", "Reserved", base.DEC)
fields.Header = ProtoField.string(NAME .. ".Header", "Header", base.ASCII)
fields.Body = ProtoField.string(NAME .. ".Body", "Body", base.ASCII)

-- 3. Protocol Decoder Function
function tRPCdissector(buffer, pinfo, tree)
    --取得数据长度
    local buf_len = buffer:len()

    --长度检测
    if buf_len < 16 then
        return false
    end

    -- 判断是否为 tRPC 协议
    local magic = buffer(0, 2):uint()
    if magic ~= 0x930 then
        return false
    end

    -- 检查总长度
    local total_size = buffer(4, 4):uint()
    if total_size ~= buf_len then
        return false
    end

    -- 3.1 Protocol
    pinfo.cols.protocol = trpcProto.name

    -- 3.2 Info
    pinfo.cols.info:set(" " .. pinfo.src_port .. "->" .. pinfo.dst_port)

    -- 3.3 Fields
    local subtree = tree:add(trpcProto, buffer())

    subtree:add(fields.Magic, buffer(0, 2))
    subtree:add(fields.FrameType, buffer(2, 1))
    subtree:add(fields.StreamFrameType, buffer(3, 1))
    subtree:add(fields.TotalLen, buffer(4, 4))
    subtree:add(fields.HeaderLen, buffer(8, 2))
    subtree:add(fields.StreamID, buffer(10, 4))
    subtree:add(fields.Version, buffer(14, 1))
    subtree:add(fields.Reserved, buffer(15, 1))

    local version = buffer(14, 1):uint()
    local headerLen = buffer(8, 2):uint()
    local header = buffer(16, headerLen)
    subtree:add(fields.Header, header)

    local totalLen = buffer(4, 4):uint()
    local body = buffer(16 + headerLen, totalLen - headerLen - 16)
    subtree:add(fields.Body, body)

    -- 3.4 finally Info
    pinfo.cols.info:append(" Len=" .. totalLen .. ", Ver=" .. version)
    pinfo.cols.info:append(" [tRPC Protocol Data]")

    return true
end

local data_dis = Dissector.get("data")

function trpcProto.dissector(buffer, pinfo, tree)
    if tRPCdissector(buffer, pinfo, tree) then
        -- success
    else
        -- data_dis 这个 dissector总是需要; 当发现不是我的协议时, 交由其他协议尝试解析
        data_dis:call(buffer, pinfo, tree)
    end
end

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    local length = buffer:len()
    if length < 8 then
        return false
    end

    local magic = buffer(0, 2):uint()
    if magic == 0x930 then
        -- 检查是否分段
        local pdu_length = buffer(4, 4):uint()
        if pdu_length > buffer:len() then
            pinfo.desegment_len = pdu_length - buffer:len()
        else
            trpcProto.dissector(buffer, pinfo, tree)
        end
        return true
    else
        return false
    end
end

-- 4. Register decoder to wireshark
trpcProto:register_heuristic("tcp", heuristic_checker)
