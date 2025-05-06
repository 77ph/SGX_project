# SGX SDK settings
SGX_SDK ?= /opt/intel/sgxsdk
SGX_ARCH ?= x64

ifeq ($(SGX_ARCH), x86)
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
else
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
endif

# Compiler settings
CC = gcc
CFLAGS = -m64 -O2 -fPIC -fvisibility=hidden -fstack-protector -nostdinc -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I./include -I./src -DSECP256K1_ENABLE_MODULE_RECOVERY=1

# Source files
SRC_FILES = src/secp256k1.c src/precomputed_ecmult.c src/precomputed_ecmult_gen.c src/sgx_stubs.c src/recovery.c

# Object files
OBJ_FILES = $(SRC_FILES:.c=.o)

# Target library
TARGET = libsecp256k1.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ_FILES) 
