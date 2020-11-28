
.PHONY: default all clean build

# include dirs
include_dir=/usr/local/include/lua
# targets
targets = wgo.so parse_pb.so

default: build
all: build

build: ${targets}

# 1 generate cgo
parse_pb.so: parser/parse_pb.go parser/dao.go
	cd parser
	go build -o $@ -buildmode=c-shared $^ 
	cd ..

# 2 gen c so
wgo.so: c/wgo.c
	gcc -shared -Wall -O2 -g -I${include_dir} -undefined dynamic_lookup  $^ -o $@

clean:
	rm -rf ${targets}  ${targets}.dSYM

