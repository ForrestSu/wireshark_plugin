package tencent

import (
	"net/url"
	"strings"

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
	// query := parsePairs(req.Params)
	// vid := query.GetStr("vid")
	// if len(vid) != 11 {
	// 	return nil, fmt.Errorf("Nil")
	// }
	// _ = WriteFile("/tmp/vid.txt", []byte(vid+"\n"), 0777)
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

// KvMap alias map
type KvMap map[string]string

// parser params or cookies, both like ["vid=b0033ab5vky", "cid=mzc00200", ...]
func parsePairs(pairs []string) KvMap {
	retMap := make(KvMap)
	for _, pair := range pairs {
		pos := strings.IndexByte(pair, '=')
		if pos < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:pos])
		originValue := pair[pos+1:]
		val, err := url.QueryUnescape(originValue)
		if err != nil {
			val = originValue
		}
		if len(key) == 0 || len(val) == 0 {
			continue
		}
		retMap[key] = val
	}
	return retMap
}

// GetStr str
func (m KvMap) GetStr(key string) string {
	if val, ok := m[key]; ok {
		return val
	}
	return ""
}
