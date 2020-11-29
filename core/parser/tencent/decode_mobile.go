package tencent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/ForrestSu/wireshark_plugin/core/parser/codec"

	aid_module "github.com/ForrestSu/wireshark_plugin/core/parser/tencent/stub/aid_module"

	"git.code.oa.com/jce/jce"
	vp "git.code.oa.com/videocommlib/videopacket-go"
)

// 注册协议 Codec
func init() {
	codec.Register("Qjce", mobileReq{})
	codec.Register("Ajce", mobileRsp{})
}

type mobileReq struct{}

func (mobileReq) Decode(data []byte) ([]byte, error) {
	return doParse(data, &aid_module.GetAidRequest{})
}

type mobileRsp struct{}

func (mobileRsp) Decode(data []byte) ([]byte, error) {
	return doParse(data, &aid_module.GetAidResponse{})
}

func doParse(data []byte, msg jce.Message) ([]byte, error) {
	// 读取包头
	header := vp.NewVideoPacket()
	if err := header.Decode(data); err != nil {
		return nil, fmt.Errorf("fail decode videopacket header! err: %+v", err)
	}
	// 反序列化 body
	jsonBody, err := unmarshalBody([]byte(header.CommHeader.Body), msg)
	if err != nil {
		return nil, err
	}
	seqID := header.CommHeader.BasicInfo.SeqId
	header.CommHeader.Body = string(jsonBody)
	jsonData, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return addSeqAtHeader(seqID, jsonData)
}

func unmarshalBody(body []byte, msg jce.Message) ([]byte, error) {
	if err := jce.Unmarshal(body, msg); err != nil {
		return nil, err
	}
	return json.Marshal(msg)
}

// add 9 bytes header! <'$'+int64(seq)+json>
func addSeqAtHeader(seqID int64, jsonData []byte) ([]byte, error) {
	var sb = &bytes.Buffer{}
	sb.Grow(len(jsonData) + 9)
	sb.WriteByte('$')
	if err := binary.Write(sb, binary.BigEndian, seqID); err != nil {
		return nil, err
	}
	sb.Write(jsonData)
	return sb.Bytes(), nil
}
