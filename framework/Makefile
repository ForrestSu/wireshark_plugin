
subdirs = parser c
tasks = before $(subdirs)

.PHONY: clean test $(tasks) 

default: $(tasks)

# 1 准备工作
before:
	mkdir -p build

# 2 生成相关 so
$(subdirs):
	make -C $@ $(TARGET)

# 3 在build文件夹, 进行单元测试 (此步骤可选, 用于调试开发)
test:
	cp -r test_cases/* build/
	make -C build $(TARGET)

clean:
	rm -rf build