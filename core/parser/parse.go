package main

/*
#include "stdlib.h"
*/
import "C"

import (
	"unsafe"

	"github.com/ForrestSu/wireshark_plugin/core/parser/codec"
	_ "github.com/ForrestSu/wireshark_plugin/core/parser/examples"
	_ "github.com/ForrestSu/wireshark_plugin/core/parser/tencent"
)

// doParse 协议解析入口
func doParse(name string, msg []byte) string {
	p := codec.GetCodec(name)
	decoded, err := p.Decode(msg)
	if err != nil {
		return err.Error()
	}
	return string(decoded)
}

//export Parse
func Parse(name string, msg string) (*C.char, int) {
	goStr := doParse(name, []byte(msg))
	// https://stackoverflow.com/questions/48686763/cgo-result-has-go-pointer
	return C.CString(goStr), len(goStr)
}

//export FreeGoString
func FreeGoString(goStr *C.char) {
	C.free(unsafe.Pointer(goStr))
}

func main() {
}
