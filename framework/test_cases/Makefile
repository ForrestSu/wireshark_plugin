
.PHONY: default

CPP_FLAGS = -Wall -O2 -g -std=c++11

default: cpp_call_golang

## demo
cpp_call_golang: cpp_call_golang.cpp
	g++ $(CPP_FLAGS) $^ -L. -lparse_pb  -o $@
	./$@
