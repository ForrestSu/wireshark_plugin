package tencent

import (
	"github.com/ForrestSu/wireshark_plugin/core/parser/codec"
	"github.com/ForrestSu/wireshark_plugin/core/parser/tencent/stub/ad_packet"

	"github.com/golang/protobuf/proto"
)

// 注册协议 Codec
func init() {
	codec.Register("Qpb", aidReq{})
	codec.Register("Apb", aidRsp{})
}

// aidReq aid 请求包
type aidReq struct{}

func (aidReq) Decode(data []byte) ([]byte, error) {
	req := &ad_packet.Request2Adaptor{}
	if err := proto.Unmarshal(data, req); err != nil {
		return nil, err
	}
	return req.MarshalJSON()
}

// aidRsp aid 应答包
type aidRsp struct{}

func (aidRsp) Decode(data []byte) ([]byte, error) {
	rsp := &ad_packet.ResponseFromAdaptor{}
	if err := proto.Unmarshal(data, rsp); err != nil {
		return nil, err
	}
	return rsp.MarshalJSON()
}
