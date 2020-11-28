
.PHONY: default

# src
gosrc = $(wildcard *.go)

default: libparser.so

# 1 generate so
libparser.so: $(gosrc)
	go build -o $@ -buildmode=c-shared $^ 
	# move to build dir
	mv $@ libparser.h ../build/ 
