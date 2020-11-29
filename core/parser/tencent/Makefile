.PHONY: default

default: gen_pb

# 协议生成
gen_pb:
	protoc -Iprotos --go_out=./stub/ad_packet/ ./protos/ad_packet.proto
	trpc4videopacket -module aid_module -serviceName jce.aid.module -json-omitempty -outdir ./stub/aid_module ./protos/aid_module.jce
