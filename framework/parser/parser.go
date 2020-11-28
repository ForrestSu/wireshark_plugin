// parser.go
package main

import "C"

// 入口: 支持各种协议解析
func parserImpl(name string, msg *string) *string {
	if len(name) <= 0 {
		ret := "err: name is empty!"
		return &ret
	}
	// default is pb
	return ParserPB(msg)
}

//export Parser
func Parser(name, msg string) *C.char {
	gostr := parserImpl(name, &msg)
	return C.CString(*gostr)
}

func main() {
}
