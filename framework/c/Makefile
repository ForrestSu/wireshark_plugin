
.PHONY: default

# include dirs
include_dir=/usr/local/include/lua
libs = -llua 
libs += -L../build -lparser

default: go_caller.so

# 1 generate so
go_caller.so: go_caller.c parser.c
	gcc -shared -Wall -O2 -g -I$(include_dir) $(libs) $^ -o $@
	mv $@ ../build/
	rm -rf $@.dSYM
	
