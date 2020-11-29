package main

type UserInfo struct {
	Name    string `json:"name,omitempty"` //name
	Message string `json:"message,omitempty"` //消息
	Length  int32  `json:"length,omitempty"`  //消息大小
	Cnt     int32  `json:"cnt,omitempty"`     //消息计数
}
