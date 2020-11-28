
.PHONY: default

default: libparse_pb.so

# 1 generate so
libparse_pb.so: parse_pb.go dao.go
	go build -o $@ -buildmode=c-shared $^ 
	# move to build dir
	mv $@ libparse_pb.h ../build/ 
