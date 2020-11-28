
.PHONY: default

# include dirs
include_dir=/usr/local/include/lua

default: wgo.so

# 1 generate so
wgo.so: wgo.c
	gcc -shared -Wall -O2 -g -I$(include_dir) -undefined dynamic_lookup  $^ -o $@
	mv $@ ../build/
	rm -rf $@.dSYM
	
