package examples

import (
	"encoding/json"

	"github.com/ForrestSu/wireshark_plugin/core/parser/codec"
	"github.com/ForrestSu/wireshark_plugin/core/parser/examples/stub/hello"
	"google.golang.org/protobuf/proto"
)

// 注册协议 Codec
func init() {
	codec.Register("hello-req", helloReq{})
	codec.Register("hello-rsp", helloRsp{})
}

// 解析请求
type helloReq struct{}

func (helloReq) Decode(data []byte) ([]byte, error) {
	return decodeToJSON(data, &hello.HelloRequest{})
}

type helloRsp struct{}

func (helloRsp) Decode(data []byte) ([]byte, error) {
	return decodeToJSON(data, &hello.HelloReply{})
}

// decodeToJSON 解码后,然后再序列化为json
func decodeToJSON(data []byte, msg proto.Message) ([]byte, error) {
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return json.Marshal(msg)
}
