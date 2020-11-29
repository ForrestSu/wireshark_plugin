package codec

import (
	"fmt"
	"sync"
)

// Codec 协议解码接口
type Codec interface {
	// Decode 实现解码逻辑，然后序列化为 json 返回
	Decode(data []byte) ([]byte, error)
}

var (
	gCodecs = make(map[string]Codec)
	lock    sync.RWMutex
)

// Register 通过协议名注册 Codec
func Register(name string, msgCodec Codec) {
	lock.Lock()
	gCodecs[name] = msgCodec
	lock.Unlock()
}

// GetCodec 通过 codec name 获取 codec
func GetCodec(name string) Codec {
	if c, ok := gCodecs[name]; ok {
		return c
	}
	return noop{}
}

type noop struct{}

func (noop) Decode(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("un-support proto")
}
