-- @brief  Wireshark plugin for ad_packet Protocol
-- @date   2020.10.30
-- @doc    https://wiki.wireshark.org/LuaAPI

local ProtoTypeText = {
    [0x0] = "Unknown",
    [0x1] = "Protocol Buffer",
    [0x2] = "JSON"
}

-- 1. Create Protocol Object
local NAME = "ad_packet"
local sqProto = Proto(NAME, "PCG ad_packet Protocol")

-- 2. Define Protocol Fields
local fields = sqProto.fields
fields.Version = ProtoField.uint32(NAME .. ".Version", "Version", base.DEC)
fields.SocketFd = ProtoField.uint32(NAME .. ".SocketFd", "SocketFd", base.DEC)
fields.Seq = ProtoField.uint32(NAME .. ".Seq", "Seq", base.DEC)
fields.TotalLen = ProtoField.uint32(NAME .. ".TotalLen", "TotalLen", base.DEC)
fields.Body = ProtoField.string(NAME .. ".Body", "Body", base.ASCII)

-- 3. Protocol Decoder Function
function adPacket_dissector(buffer, pinfo, tree)
    --取得数据长度
    local buf_len = buffer:len()

    --长度检测
    if buf_len < 16 then
        return false
    end

    -- 判断是否为 ad_packet 协议
    local total_size = buffer(12, 4):uint()
    if total_size ~= buf_len then
        return false
    end

    -- 3.1 Protocol
    pinfo.cols.protocol = sqProto.name

    -- 3.2 Info
    pinfo.cols.info:set(" " .. pinfo.src_port .. "->" .. pinfo.dst_port)

    -- 3.3 Fields
    local subtree = tree:add(sqProto, buffer())

    local version = buffer(0, 4):uint()
    subtree:add(fields.Version, version)

    local socketfd = buffer(4, 4)
    subtree:add(fields.SocketFd, socketfd)

    local seq = buffer(8, 4)
    subtree:add(fields.Seq, seq)

    local total_len = buffer(12, 4)
    subtree:add(fields.TotalLen, total_len)

    local body = buffer(16, buf_len - 16)
    subtree:add(fields.Body, body)

    -- 3.4 finally Info
    pinfo.cols.info:append(" Len=" .. total_size .. ", Ver=" .. version .. ", Seq=" .. seq:uint())
    pinfo.cols.info:append(" [ad_packet Protocol Data]")

    return true
end

local data_dis = Dissector.get("data")

function sqProto.dissector(buffer, pinfo, tree)
    if adPacket_dissector(buffer, pinfo, tree) then
        -- success
    else
        -- data_dis 这个 dissector总是需要; 当发现不是我的协议时, 交由其他协议尝试解析
        data_dis:call(buffer, pinfo, tree)
    end
end

-- 4. Register decoder to wireshark
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(10011, sqProto)
