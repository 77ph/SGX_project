# SGX SDK settings
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_MODE), HW)
    ifeq ($(SGX_DEBUG), 1)
        DEBUG_FLAGS := -g3 -ggdb -O0 -DDEBUG
        SGX_COMMON_FLAGS := -m64 -DDEBUG -UNDEBUG -UEDEBUG -DSGX_HW
    else
        DEBUG_FLAGS := -O2 -DNDEBUG -g3 -ggdb
        SGX_COMMON_FLAGS := -m64 -DNDEBUG -UEDEBUG -UDEBUG -DSGX_HW
    endif
else
    SGX_DEBUG := 1
    DEBUG_FLAGS := -g3 -ggdb -O0 -DDEBUG
    SGX_COMMON_FLAGS := -m64 -DDEBUG -UNDEBUG -UEDEBUG -DSGX_SIM
endif

SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

# Export LD_LIBRARY_PATH
export LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):$(SGX_LIBRARY_PATH)

# Common flags for both HW and SIM modes
SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wconversion -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

# App settings
App_Cpp_Files := App/App.cpp App/sgx_utils/sgx_utils.cpp
App_Include_Paths := -I$(SGX_SDK)/include -IApp -IApp/sgx_utils
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Flags := $(SGX_COMMON_CFLAGS) $(DEBUG_FLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) $(SGX_COMMON_CXXFLAGS)

ifeq ($(SGX_MODE), HW)
    App_Link_Flags := $(SGX_COMMON_FLAGS) -L$(SGX_SDK)/lib64 -lsgx_urts -lsgx_uae_service -lpthread
else
    App_Link_Flags := $(SGX_COMMON_FLAGS) -L$(SGX_SDK)/lib64 -lsgx_urts_sim -lsgx_uae_service_sim -lpthread
endif

# Enclave settings
Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -IEnclave
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) $(SGX_COMMON_CXXFLAGS) -nostdinc++

ifeq ($(SGX_MODE), HW)
    Enclave_Link_Flags := $(SGX_COMMON_FLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
        -Wl,--version-script=Enclave/Enclave.lds
else
    Enclave_Link_Flags := $(SGX_COMMON_FLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
        -Wl,--version-script=Enclave/Enclave.lds
endif

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Private_Key := Enclave/Enclave_private.pem

# Targets
.PHONY: all clean

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

ifeq ($(SGX_MODE), HW)
all: .config_$(Build_Mode)_$(SGX_ARCH) app enclave.signed.so
	@echo "Build app $(Build_Mode) $(SGX_ARCH) success"
else
all: .config_$(Build_Mode)_$(SGX_ARCH) app enclave.so
	@echo "Build app $(Build_Mode) $(SGX_ARCH) success"
endif

.config_$(Build_Mode)_$(SGX_ARCH): $(Enclave_Config_File)
	@echo "Building for $(Build_Mode) mode"
	@touch $@

App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.c: App/Enclave_u.h
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

app: App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

enclave.so: Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

enclave.signed.so: enclave.so
	$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Private_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File) -ignore-rel-error -ignore-init-sec-error
	@chmod +x $@
	@echo "SIGN =>  $@"

clean:
	rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@echo "Clean completed."
