// parser_pb.go
package main

import (
	"encoding/json"
	"fmt"
)

func ParserPB(msg string) string {
	user := &UserInfo{
		Message: msg,
		Length:  100,
		Cnt:     50,
	}
	if data, err := json.Marshal(user); err == nil {
		return string(data)
	} else {
		return fmt.Sprintf("err: %+v", err)
	}
}
