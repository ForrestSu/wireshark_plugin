-- @brief  Wireshark plugin for ad_packet Protocol
-- @date   2020.10.30
-- @doc    https://wiki.wireshark.org/LuaAPI

-- video_packet 使用的端口
local PortUsed = 10018

-- 1. Create Protocol Object
local NAME = "vp_header"
local headerProto = Proto(NAME, "PCG vp header")

-- 2. Define Protocol Fields
local fields = headerProto.fields
fields.Stx = ProtoField.uint8(NAME .. ".stx", "stx", base.HEX)
fields.TotalLen = ProtoField.uint32(NAME .. ".totalLen", "TotalLen", base.DEC)
fields.Version = ProtoField.uint8(NAME .. ".version", "Version", base.DEC)
fields.Reserves = ProtoField.bytes(NAME .. ".reserve", "Reserve", base.SPACE)
fields.Seq = ProtoField.uint64(NAME .. ".seq", "Seq", base.DEC)
fields.Type = ProtoField.bool(NAME .. ".type", "isRequest")
fields.ref_req = ProtoField.framenum(NAME .. ".seq_num", "Request frame", base.NONE, frametype.REQUEST)
fields.ref_rsp = ProtoField.framenum(NAME .. ".seq_num", "Response frame", base.NONE, frametype.RESPONSE)

-- 定义 video packet pb 消息
local VP_NAME = "VIDEO_PACKET"
local videoProto = Proto(VP_NAME, "PCG Video Packet Protocol")

local pb_fields = videoProto.fields
pb_fields.tojson = ProtoField.string(VP_NAME .. ".tojson", "toJson", base.ASCII)

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
function jcePacket_dissector(buffer, pinfo, tree)
    -- 取得数据长度
    local buf_len = buffer:len()
    local MinPacketLen = 17
    -- 最小长度检测
    if buf_len < MinPacketLen then
        return false
    end
    -- stx = 0x26
    stx = buffer(0, 1):uint()
    if stx ~= 0x26 then
        return false
    end

    -- tcp multi segments
    local total_len = buffer(1, 4):uint()
    if buf_len < total_len then
        pinfo.desegment_len = total_len - buf_len
        return true
    end

    -- 判断是否为完整的 jce 协议
    if buf_len ~= total_len then
        return false
    end

    -- 如果源端口不为 10018, 说明是请求包
    local is_req_packet = (pinfo.src_port ~= PortUsed)

    -- 3.1 Protocol
    pinfo.cols.protocol = videoProto.name

    -- 3.2 Info
    pinfo.cols.info:set(" " .. pinfo.src_port .. "->" .. pinfo.dst_port)

    local jce_tree = tree:add(videoProto, buffer())

    -- 3.3 Fields
    local header_tree = jce_tree:add(headerProto, buffer(0, 16))
    header_tree:add(fields.Stx, buffer(0, 1))
    header_tree:add(fields.TotalLen, buffer(1, 4))

    local version = buffer(5, 1)
    header_tree:add(fields.Version, version)
    header_tree:add(fields.Reserves, buffer(6, 10)) -- reserve 10 bytes

    header_tree:add(fields.Type, is_req_packet)

    -- if only header
    if buf_len == MinPacketLen then
        return true
    end

    local vp_body = buffer(0, buf_len)
    --  解析jce
    local seqId, ref_id = jce_dissector(is_req_packet, header_tree, vp_body, pinfo, jce_tree)

    -- 3.4 finally Info
    local content = " Len=" .. total_len .. ", SeqId=" .. seqId .. ", Ver=" .. version:uint()
    if is_req_packet then
        pinfo.cols.info:append(" request" .. content .. " (reply in " .. ref_id .. ")")
    else
        pinfo.cols.info:append(" reply" .. content .. " (request in " .. ref_id .. ")")
    end
    return true
end

-- 加载库
local wgo = require "go_caller"
-- local json = require "json"
local json_dis = Dissector.get("json")

-- 解析 jce 协议, 并展示。多返回值
function jce_dissector(is_req_packet, header_tree, body, pinfo, jce_tree)
    local proto_name
    if is_req_packet then
        proto_name = "Qjce"
    else
        proto_name = "Ajce"
    end
    -- to lua string
    local input_lua_str = body:raw(body:offset(), body:len())
    local decoded_str = wgo.parser(proto_name, input_lua_str)
    -- get reqId if start with '$'
    local seqId = 0
    local ref_id = 0
    local json_str = ""
    if string.sub(decoded_str, 1, 1) == '$' then
        local seqStr = string.sub(decoded_str, 2, 9)
        local seqBytes = ByteArray.new(seqStr, true)
        local seqTvb = ByteArray.tvb(seqBytes, "SeqId")
        seqId = seqTvb(0, 8):int64()
        header_tree:add(fields.Seq, seqTvb(0, 8))
        -- 请求包和应答包匹配
        ref_id = show_refId_ink(is_req_packet, pinfo, seqId, header_tree)

        json_str = string.sub(decoded_str, 10) -- start is 10
        -- show json tree
        -- local byteArr = ByteArray.new(json_str, true)
        -- local tvb = ByteArray.tvb(byteArr, "JsonTree")
        -- json_dis:call(tvb, pinfo, jce_tree)
    else
        json_str = decoded_str
    end

    -- 循环显示一个长字符串
    local json_tree = jce_tree:add(pb_fields.tojson, json_str)
    show_long_string(json_tree, json_str)
    return seqId, ref_id
end

-- 返回
function show_refId_ink(is_req_packet, pinfo, seq, tree_node)
    local ref_id
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

function videoProto.dissector(buffer, pinfo, tree)
    if jcePacket_dissector(buffer, pinfo, tree) then
        -- if return true, is success
    else
        -- data_dis 这个 dissector总是需要; 当发现不是我的协议时, 交由其他协议尝试解析
        data_dis:call(buffer, pinfo, tree)
    end
end

-- 4. Register decoder to wireshark
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(PortUsed, videoProto)
