
.PHONY: default clean install

# wireshark 插件目录
plugin_dir=~/.local/lib/wireshark/plugins
# wireshark so 插件目录
so_dir=${plugin_dir}/plugin_so_dir

default: install
all: install_deps  install

install_deps:
	cp libs/pb.so ${so_dir}
	cp libs/json.lua ${plugin_dir}

install:
	cp ad_packet_pb.lua ${plugin_dir}
	