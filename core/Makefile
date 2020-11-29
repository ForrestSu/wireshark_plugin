# lua5.2 动态库目录
so_dir=/usr/local/lib/lua/5.2
# wireshark 插件目录
lua_plugin_dir=~/.local/lib/wireshark/plugins

## tasks
subdirs = parser c
tasks = before $(subdirs)

.PHONY: clean test $(tasks) install

default: $(tasks)

# 1 准备工作
before:
	mkdir -p build
	mkdir -p $(so_dir)

# 2 生成相关 so
$(subdirs):
	make -C $@ $(TARGET)

# 3 在build文件夹, 进行单元测试 (此步骤可选, 用于调试开发)
test:
	cp -r test_cases/* build/
	make -C build $(TARGET)

## 安装
install: default
	cp build/libparser.so $(so_dir)
	cp build/go_caller.so $(so_dir)
	cp ws-lua/*.lua $(lua_plugin_dir)
	# fix rpath
	install_name_tool -change  libparser.so $(so_dir)/libparser.so  $(so_dir)/go_caller.so

clean:
	rm -rf build