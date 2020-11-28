
subdirs = c parser
tasks = before $(subdirs) after

.PHONY: clean $(tasks)

default: $(tasks)

# 1 准备工作
before:
	mkdir -p build
# 2 生成相关 so
$(subdirs):
	make -C $@ $(TARGET)

# 3 在build文件夹, 编译测试代码
after:
	cp -r test_cases/* build/
	make -C build $(TARGET)

clean:
	rm -rf build