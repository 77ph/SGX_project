# Компилятор и флаги
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -O2
CXXFLAGS = -Wall -Wextra -O2

# Пути к SGX SDK
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

# Check architecture
ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

# Имена файлов
ENCLAVE_NAME = libenclave
APP_NAME = app

# Исходные файлы
ENCLAVE_SOURCES = Enclave/Enclave.cpp
APP_SOURCES = App/App.cpp

# Объектные файлы
ENCLAVE_OBJS = $(ENCLAVE_SOURCES:.cpp=.o)
APP_OBJS = $(APP_SOURCES:.cpp=.o)

# Заголовочные файлы
ENCLAVE_HEADERS = Enclave/Enclave.h Enclave/Enclave_t.h
APP_HEADERS = App/App.h

# Флаги компиляции
ENCLAVE_CFLAGS = -m64 -O2 -fPIC -fstack-protector -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -I$(SGX_SDK)/include -I.
ENCLAVE_CXXFLAGS = $(ENCLAVE_CFLAGS) -std=c++11
APP_CFLAGS = -m64 -O2 -fPIC -fstack-protector -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -I$(SGX_SDK)/include -I.
APP_CXXFLAGS = $(APP_CFLAGS) -std=c++11

# Флаги линковки
ENCLAVE_LDFLAGS = -m64 -O2 -fPIC -fstack-protector -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -L$(SGX_LIBRARY_PATH)
APP_LDFLAGS = -m64 -O2 -fPIC -fstack-protector -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fno-strict-aliasing -L$(SGX_LIBRARY_PATH) -lsgx_uprotected_fs -lpthread

# Библиотеки
ENCLAVE_LIBS = -lsgx_trts -lsgx_tcrypto -lsgx_tseal
APP_LIBS = -lsgx_urts -lsgx_uae_service

# Application settings
App_Cpp_Files := App/App.cpp App/sgx_utils/sgx_utils.cpp
App_Include_Paths := -I$(SGX_SDK)/include -IApp -IApp/sgx_utils

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lsgx_uprotected_fs -lpthread

# Enclave settings
Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_C_Files := lib/secp256k1/src/secp256k1.c \
                   lib/secp256k1/src/precomputed_ecmult.c \
                   lib/secp256k1/src/precomputed_ecmult_gen.c \
                   Enclave/sha3.c

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -IEnclave -Ilib/secp256k1/include -Ilib/secp256k1/src

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(Enclave_Include_Paths) -Wno-conversion -Wno-sign-conversion
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -lsgx_tprotected_fs -lpthread -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

# secp256k1 settings
SECP256K1_DIR := lib/secp256k1
SECP256K1_INCLUDE := -I$(SECP256K1_DIR)/include

# Generate source files
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

App_Name := app
Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so

.PHONY: all run

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

ifeq ($(Build_Mode), HW_RELEASE)
	Enclave_Link_Flags += -Wl,-O2
	App_Link_Flags += -Wl,-O2
else
	Enclave_Link_Flags += -g
	App_Link_Flags += -g
endif

all: .config_$(Build_Mode)_$(SGX_ARCH) $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name)

.config_$(Build_Mode)_$(SGX_ARCH):
	@echo "Building for $(Build_Mode) mode"
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########
App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/App.o: App/App.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

App/sgx_utils/sgx_utils.o: App/sgx_utils/sgx_utils.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o App/App.o App/sgx_utils/sgx_utils.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########
Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/Enclave.o: Enclave/Enclave.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

# Rule for compiling .c files
Enclave/sha3.o: Enclave/sha3.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o Enclave/Enclave.o $(Enclave_C_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config Enclave/Enclave.config.xml
	@echo "SIGN =>  $@"

# secp256k1 object files
lib/secp256k1/src/secp256k1.o: lib/secp256k1/src/secp256k1.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

lib/secp256k1/src/precomputed_ecmult.o: lib/secp256k1/src/precomputed_ecmult.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

lib/secp256k1/src/precomputed_ecmult_gen.o: lib/secp256k1/src/precomputed_ecmult_gen.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_C_Objects) $(Enclave_Cpp_Objects) App/Enclave_u.* Enclave/Enclave_t.*
	@echo "Clean completed."

# Запуск тестов
test: all
	python3 test_account_pool.py

.PHONY: all clean test
