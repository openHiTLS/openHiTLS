# C 目标可执行文件
TARGET = test_lib

# C 源文件
SRCS = test_lib.c

# 头文件路径
INCLUDE_DIRS = \
    -I$(INC_HITLS_PATH)/crypto \
    -I$(INC_HITLS_PATH)/bsl

# 库路径
LIB_DIR = $(LIB_HITLS)

# 库名称
LIBS = -lhitls_crypto -lhitls_bsl -lboundscheck

# C 编译器和链接器
CC = gcc

# C 编译选项
CFLAGS = $(INCLUDE_DIRS)

# C 链接选项
LDFLAGS = -L$(LIB_DIR) $(LIBS)

default: test_lib

# 构建 C 程序
test_lib: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

# 清理生成的文件
clean:
	rm -f $(TARGET) $(TARGET)

# 帮助信息
help:
	@echo "Makefile Usage:"
	@echo "  make          - Build the Go program (alias for 'make go')."
	@echo "  make test_lib - Build the C program."
	@echo "  make clean    - Remove the generated executables."
	@echo "  make help     - Show this help message."