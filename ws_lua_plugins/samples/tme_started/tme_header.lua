-- @brief  Wireshark plugin for TME RPC Protocol
-- @author delphisfang
-- @date   2019.12.26
-- @doc    https://wiki.wireshark.org/LuaAPI


local MagicText = {
[0x24454d54] = "$EMT",
[0x544d4524] = "TME$",
}

local ProtoTypeText = {
[0x0] = "Unknown",
[0x1] = "Protocol Buffer",
[0x2] = "JSON",
}

local HeadTypeText = {
[0x0] = "Unknown",
[0x1] = "Request",
[0x2] = "Response",
}

-- 1. Create Protocol Object
local NAME = "Hades"
local hadesProto = Proto(NAME, "TME RPC Protocol")

-- 2. Define Protocol Fields
local fields = hadesProto.fields
fields.Magic      = ProtoField.uint32(NAME .. ".Magic", "Magic", base.HEX, MagicText)
fields.Version    = ProtoField.uint8(NAME .. ".Version", "Version")
fields.ProtoType  = ProtoField.uint8(NAME .. ".ProtoType", "ProtoType", base.DEC, ProtoTypeText)
fields.HeadType   = ProtoField.uint16(NAME .. ".HeadType", "HeadType", base.DEC, HeadTypeText)
fields.ModuleId   = ProtoField.uint32(NAME .. ".ModuleId", "ModuleId")
fields.AppId      = ProtoField.uint32(NAME .. ".AppId", "AppId")
fields.Uid        = ProtoField.uint64(NAME .. ".Uid", "Uid")
fields.SpanId     = ProtoField.uint64(NAME .. ".SpanId", "SpanId")
fields.TimeoutMs  = ProtoField.uint32(NAME .. ".TimeoutMs", "TimeoutMs")
fields.Flag       = ProtoField.uint32(NAME .. ".Flag", "Flag")
fields.ResultCode = ProtoField.int32(NAME .. ".ResultCode", "ResultCode")
fields.BodyLen    = ProtoField.uint32(NAME .. ".BodyLen", "BodyLen")
fields.ServiceLen = ProtoField.uint16(NAME .. ".ServiceLen", "ServiceLen")
fields.TraceidLen = ProtoField.uint16(NAME .. ".TraceidLen", "TraceidLen")
fields.ExtHeadLen = ProtoField.uint32(NAME .. ".ExtHeadLen", "ExtHeadLen")
fields.ServiceName = ProtoField.string(NAME .. ".ServiceName", "ServiceName", base.ASCII)
fields.TraceId     = ProtoField.string(NAME .. ".TraceId", "TraceId", base.ASCII)
fields.ExtHead     = ProtoField.string(NAME .. ".ExtHead", "ExtHead", base.ASCII)

local data_dis = Dissector.get("data")

-- 3. Protocol Decoder Function
function hades_dissector(tvb, pinfo, tree)

  -- 3.1 Protocol
  pinfo.cols.protocol = hadesProto.name
  
  -- 3.2 Info
  pinfo.cols.info:set(" " ..pinfo.src_port .. "->" .. pinfo.dst_port)
  pinfo.cols.info:append(" [TME RPC Protocol Data]")

  -- 3.3 Fields
  local subtree = tree:add(hadesProto, tvb())

  local magic = tvb(0, 4)
  subtree:add(fields.Magic, magic)

  local version = tvb(4, 1)
  subtree:add(fields.Version, version)

  local protoType = tvb(5, 1)
  subtree:add(fields.ProtoType, protoType)

  local headType = tvb(6, 2)
  subtree:add(fields.HeadType, headType)

  local moduleId = tvb(8, 4)
  subtree:add(fields.ModuleId, moduleId)

  local appId = tvb(12, 4)
  subtree:add(fields.AppId, appId)

  local uid = tvb(16, 8)
  subtree:add(fields.Uid, uid)

  local spanId = tvb(24, 8)
  subtree:add(fields.SpanId, spanId)

  local timeoutMs = tvb(32, 4)
  subtree:add(fields.TimeoutMs, timeoutMs)

  local flag = tvb(36, 4)
  subtree:add(fields.Flag, flag)

  local resultCode = tvb(40, 4)
  subtree:add(fields.ResultCode, resultCode)

  local bodyLen = tvb(44, 4):uint()
  subtree:add(fields.BodyLen, tvb(44, 4))

  local serviceLen = tvb(48, 2):uint()
  subtree:add(fields.ServiceLen, tvb(48, 2))

  local traceidLen = tvb(50, 2):uint()
  subtree:add(fields.TraceidLen, tvb(50, 2))

  local extHeadLen = tvb(52, 4):uint()
  subtree:add(fields.ExtHeadLen, tvb(52, 4))

  local serviceName = tvb(56, serviceLen)
  subtree:add(fields.ServiceName, tvb(56, serviceLen))
  
  local traceId = tvb(56+serviceLen, traceidLen)
  subtree:add(fields.TraceId, tvb(56+serviceLen, traceidLen))

  local extHead = tvb(56+serviceLen+traceidLen, extHeadLen)
  subtree:add(fields.ExtHead, tvb(56+serviceLen+traceidLen, extHeadLen))

end

function hadesProto.dissector(tvb, pinfo, tree)
    ret = hades_dissector(tvb, pinfo, tree)
    if ret == 1 then
        -- pass
    else
        data_dis:call(tvb, pinfo, tree)
    end
end

-- 4. Register decoder to wireshark
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(11219, hadesProto)

