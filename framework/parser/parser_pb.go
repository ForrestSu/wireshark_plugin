// parser_pb.go
package main

import (
	"encoding/json"
	"fmt"
)

func ParserPB(name, msg *string) *string {
	user := &UserInfo{
		Name:  *name,
		Message: *msg,
		Length:  100,
		Cnt:     50,
	}
	var ret string
	if data, err := json.Marshal(user); err == nil {
		ret = string(data)
	} else {
		ret = fmt.Sprintf("err: %+v", err)
	}
	return &ret
}
