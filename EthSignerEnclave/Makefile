# SGX SDK settings
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(SGX_ARCH), x86)
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

# App settings
App_Cpp_Files := App/App.cpp App/sgx_utils/sgx_utils.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Flags := -m64 -O2 -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -m64 -L$(SGX_LIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lpthread
App_Name := app

# Enclave settings
Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/sgx_metadata.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -Ilib/secp256k1/include
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Flags := -m64 -O2 -fpie -fstack-protector-strong -nostdinc -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -Ilib/secp256k1/include -fvisibility=default -ffunction-sections -fdata-sections
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++ -fvisibility=default
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tservice -lsgx_tcrypto -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--export-dynamic -Wl,--version-script=Enclave/Enclave.lds \
    -Llib/secp256k1 -l:libsecp256k1.a

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Private_Key := Enclave/Enclave_private.pem

# Targets
.PHONY: all clean

all: $(App_Name) $(Signed_Enclave_Name)

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Private_Key) -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) -Wl,--whole-archive Enclave/Enclave_t.o -Wl,--no-whole-archive $(Enclave_Cpp_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -fno-common -fPIC -fvisibility=default -DSGX_EXTERNC= -fno-stack-protector -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	$(CXX) $(Enclave_Cpp_Flags) -fvisibility=default -c $< -o $@
	@echo "CXX  <=  $<"

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

clean:
	rm -f $(App_Name) $(Signed_Enclave_Name) $(Enclave_Name) \
	      App/*.o App/Enclave_u.* Enclave/*.o Enclave/Enclave_t.*
	@echo "Clean completed."
