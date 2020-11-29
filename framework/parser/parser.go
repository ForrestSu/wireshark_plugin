// parser.go
package main

/*
#include "stdlib.h"
*/
import "C"

import (
	"unsafe"
)

// 入口: 支持各种协议解析
func parserImpl(name, msg *string) *string {
	if len(*name) <= 0 {
		ret := "err: name is empty!"
		return &ret
	}
	// default is pb
	return ParserPB(name, msg)
}

//export Parser
func Parser(name, msg string) (*C.char, int) {
	gostr := parserImpl(&name, &msg)
	return C.CString(*gostr), 10
}

//export FreeCString
func FreeCString(cstr *C.char) {
	C.free(unsafe.Pointer(cstr))
}

func main() {
}
