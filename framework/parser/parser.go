// parser.go
package main

import "C"

// 入口: 支持各种协议解析
func parserImpl(name, msg string) string {
	if len(name) <= 0 {
		return "err: name is empty!"
	}
	// default is pb
	return ParserPB(msg)
}

//export Parser
func Parser(name, msg string) *C.char {
	gostr := parserImpl(name, msg)
	return C.CString(gostr)
}

func main() {
}
