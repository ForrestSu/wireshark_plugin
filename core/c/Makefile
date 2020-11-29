
.PHONY: default

# include dirs
include_dir=/usr/local/include/lua
libs = -L../build -lparser
libs += -undefined dynamic_lookup

default: go_caller.so

# 1 generate so
go_caller.so: caller.c cgo_call.c
	gcc -shared -Wall -O2 -g -I$(include_dir) $(libs) $^ -o $@
	mv $@ ../build/
	rm -rf $@.dSYM
