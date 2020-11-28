-- @brief  Wireshark plugin for ad_packet Protocol
-- @author forrestsun
-- @date   2020.10.30
-- @doc    https://wiki.wireshark.org/LuaAPI

local ProtoTypeText = {
    [0x0] = "Unknown",
    [0x1] = "Protocol Buffer",
    [0x2] = "JSON"
}

-- ad_packet使用的端口
local PortUsed = 10011

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
fields.ref_req = ProtoField.framenum(NAME .. ".seq_num", "Request frame", base.NONE, frametype.REQUEST)
fields.ref_rsp = ProtoField.framenum(NAME .. ".seq_num", "Response frame", base.NONE, frametype.RESPONSE)

-- 定义 google pb 消息
local BODY_NAME = "pb"
local body_proto = Proto(BODY_NAME, "pb request message")

local pb_fields = body_proto.fields
pb_fields.cookies = ProtoField.string(BODY_NAME .. ".cookies", "cookies", base.ASCII)
pb_fields.cookie = ProtoField.string(BODY_NAME .. ".cookie", "cookie", base.ASCII)
pb_fields.params = ProtoField.string(BODY_NAME .. ".params", "params", base.ASCII)
pb_fields.param = ProtoField.string(BODY_NAME .. ".param", "param", base.ASCII)
pb_fields.refer = ProtoField.string(BODY_NAME .. ".raw_refer", "raw_refer", base.ASCII)
pb_fields.type = ProtoField.string(BODY_NAME .. ".type", "type", base.ASCII)
pb_fields.tojson = ProtoField.string(BODY_NAME .. ".tojson", "toJson", base.ASCII)

-- 请求包缓存 <业务ID, number>
local tranId2IdRequest = {}
function cacheRequest(tid, valueId)
    tranId2IdRequest[tid] = valueId
end
function findRequestId(tid)
    id = tranId2IdRequest[tid]
    if id == nil then
        return -1
    end
    return id
end

-- 应答包缓存 <业务ID, number>
local tranId2idResp = {}
function cacheResp(tid, valueId)
    tranId2idResp[tid] = valueId
end
function findRespId(tid)
    id = tranId2idResp[tid]
    if id == nil then
        return -1
    end
    return id
end

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

    -- 如果源端口不为 10011, 说明是请求包
    local is_req_packet = (pinfo.src_port ~= PortUsed)

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

    local seq = buffer(8, 4):uint()
    subtree:add(fields.Seq, seq)

    local total_len = buffer(12, 4)
    subtree:add(fields.TotalLen, total_len)

    -- 如果是请求包,添加 frame 链接
    local ref_id
    if is_req_packet then
        -- 为了保证每个报文的唯一性(一定程度上)，故采用(port + req编号)作为transactionId
        local tid = (pinfo.src_port .. "_" .. seq)
        cacheRequest(tid, pinfo.number)
        -- 为什么生效了? 请参照下面的链接:
        -- https://ask.wireshark.org/question/1345/how-to-write-to-previous-packet-pinfo/
        ref_id = findRespId(tid)
        subtree:add(fields.ref_rsp, ref_id)
    else
        local tid = (pinfo.dst_port .. "_" .. seq)
        cacheResp(tid, pinfo.number)
        -- 查询请求cache
        ref_id = findRequestId(tid)
        subtree:add(fields.ref_req, ref_id)
    end

    local body = buffer(16, buf_len - 16)

    -- 如果是请求包
    if is_req_packet then
        local pbtree = tree:add(body_proto, body())
        pb_request_dissector(body, pbtree)
    else
        subtree:add(fields.Body, body)
    end

    -- 3.4 finally Info
    local content = " Len=" .. total_size .. ", Ver=" .. version .. ", Seq=" .. seq
    if is_req_packet then
        pinfo.cols.info:append(" request" .. content .. " (reply in " .. ref_id .. ")")
    else
        pinfo.cols.info:append(" reply  " .. content .. " (request in " .. ref_id .. ")")
    end

    return true
end

-- 加载pb
local pb = require("pb")
local protoc = require("protoc")
local json = require "json"
assert(
    protoc:load [[
syntax = "proto2";
message Request {
    enum AdReqProtocolType
    {
        UNKNOWN = 0;
        XML = 1;
        JSON = 2;
    }
    repeated string cookies = 1;
    repeated string params  = 2;
    optional bytes  raw_referer = 4;
    optional AdReqProtocolType req_protocol = 5;
} ]]
)

-- 解析PB协议, 并展示. body is a tvbrange
function pb_request_dissector(body, tree)
    -- to lua string
    local lua_str = body:raw(body:offset(), body:len())
    local request = pb.decode("Request", lua_str)
    if request == nil then
        return false
    end
    -- cookies
    if request.cookies ~= nil then
        local len = #request.cookies
        local sub_cookies = tree:add(pb_fields.cookies, "size = " .. len)
        for i = 1, #request.cookies do
            sub_cookies:add(pb_fields.cookie, request.cookies[i])
        end
    end
    -- params
    if request.params ~= nil then
        local len2 = #request.params
        local sub_params = tree:add(pb_fields.params, "size = " .. len2)
        for i = 1, #request.params do
            -- field = ProtoField.string(BODY_NAME .. ".param", "[p]", base.ASCII)
            sub_params:add(pb_fields.param, request.params[i])
        end
    end
    -- refer
    tree:add(pb_fields.refer, request.raw_referer or "<nil>")
    -- type
    tree:add(pb_fields.type, request.req_protocol or "<nil>")
    -- tojson
    json_str = json.encode(request)
    local jsontree = tree:add(pb_fields.tojson)
    -- 注意循环显示一个长字符串
    local start = 1
    while true do
        stop = start + 120
        if stop >= string.len(json_str) then
            jsontree:add(string.sub(json_str, start))
            break
        else
            jsontree:add(string.sub(json_str, start, stop))
            start = stop + 1
        end
    end
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
udp_port_table:add(PortUsed, sqProto)
