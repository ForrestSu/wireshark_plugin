.PHONY: default

default: gen_pb

# 协议生成
gen_pb:
	protoc -Iprotos --go_out=./stub/hello/ hello.proto
