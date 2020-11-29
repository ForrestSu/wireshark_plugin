-- @brief  Wireshark plugin for ad_packet Protocol
-- @date   2020.10.30
-- @doc    https://wiki.wireshark.org/LuaAPI

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
fields.Type = ProtoField.bool(NAME .. ".type", "isRequest")
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

    local version = buffer(0, 4)
    subtree:add(fields.Version, version)

    local socketfd = buffer(4, 4)
    subtree:add(fields.SocketFd, socketfd)

    local seq = buffer(8, 4):uint()
    subtree:add(fields.Seq, seq)

    local total_len = buffer(12, 4)
    subtree:add(fields.TotalLen, total_len)

    subtree:add(fields.Type, is_req_packet)

    -- only header
    if buf_len == 16 then
        return true
    end

    local ref_id = show_refId_link(is_req_packet, pinfo, seq, subtree)

    local body = buffer(16, buf_len - 16)

    -- 解析json
    local pbtree = tree:add(body_proto, body())
    pb_request_dissector(is_req_packet, body, pinfo, pbtree)

    -- 3.4 finally Info
    local content = " Len=" .. total_size .. ", Seq=" .. seq .. ", Ver=" .. version:uint()
    if is_req_packet then
        pinfo.cols.info:append(" request" .. content .. " (reply in " .. ref_id .. ")")
    else
        pinfo.cols.info:append(" reply  " .. content .. " (request in " .. ref_id .. ")")
    end
    return true
end

-- 加载库
local wgo = require "go_caller"
-- local json = require "json"
local json_dis = Dissector.get("json")

-- 解析PB协议, 并展示. body is a tvbrange
function pb_request_dissector(is_req_packet, body, pinfo, tree)
    local proto_name
    if is_req_packet then
        proto_name = "Qpb"
    else
        proto_name = "Apb"
    end
    -- to lua string
    local input_lua_str = body:raw(body:offset(), body:len())
    local decoded_str = wgo.parser(proto_name, input_lua_str)

    -- dump到本地文件
    -- if is_req_packet then
    --     if pinfo.number < 1000 then
    --         local file_name = "case_".. pinfo.number .. ".json"
    --         write_to_tmp_file(file_name, decoded_str)
    --     end
    -- end

    -- tojson
    local barr = ByteArray.new(decoded_str, true)
    local tvb = ByteArray.tvb(barr, "JsonTree")
    json_dis:call(tvb, pinfo, tree)

    local json_tree = tree:add(pb_fields.tojson, decoded_str)
    -- 注意循环显示一个长字符串
    show_long_string(json_tree, decoded_str)
    return true
end

function show_refId_link(is_req_packet, pinfo, seq, tree_node)
    local ref_id
    -- 如果是请求包,添加 frame 链接
    if is_req_packet then
        -- 为了保证每个报文的唯一性(一定程度上)，故采用(port + req编号)作为transactionId
        local tid = (pinfo.src_port .. "_" .. seq)
        cacheRequest(tid, pinfo.number)
        -- 为什么生效了? 请参照下面的链接:
        -- https://ask.wireshark.org/question/1345/how-to-write-to-previous-packet-pinfo/
        ref_id = findRespId(tid)
        tree_node:add(fields.ref_rsp, ref_id)
    else
        local tid = (pinfo.dst_port .. "_" .. seq)
        cacheResp(tid, pinfo.number)
        -- 查询请求cache
        ref_id = findRequestId(tid)
        tree_node:add(fields.ref_req, ref_id)
    end
    return ref_id
end

function write_to_tmp_file(file_name, content)
    local path = "/tmp/ad_packet/" .. file_name
    local fp = io.open(path, "w+")
    if fp then
        if fp:write(content) == nil then
            return false
        end
        io.close(fp)
        return true
    else
        return false
    end
end

-- 循环显示一个长字符串
function show_long_string(tree, json_data)
    local start = 1
    while true do
        stop = start + 120
        if stop >= string.len(json_data) then
            tree:add(string.sub(json_data, start))
            break
        else
            tree:add(string.sub(json_data, start, stop))
            start = stop + 1
        end
    end
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
