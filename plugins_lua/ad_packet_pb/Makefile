
.PHONY: default install

# lua5.2 动态库目录
so_dir=/usr/local/lib/lua/5.2
# wireshark 插件目录
lua_plugin_dir=~/.local/lib/wireshark/plugins


default: install
all: install_deps  install

install_deps:
	mkdir -p $(so_dir)
	cp libs/pb.so ${so_dir}
	cp libs/json.lua ${lua_plugin_dir}

install:
	cp ad_packet_pb.lua ${lua_plugin_dir}
	