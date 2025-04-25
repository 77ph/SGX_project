# Ethereum SGX Signer PoC

## 🛡️ Objective

Build a secure Ethereum signer that runs inside an Intel SGX enclave to protect the private key from the host OS. The enclave:

- Stores the ECDSA private key internally.
- Signs Ethereum messages and transactions without ever exposing the key.
- Exposes a minimal API (later via CLI and optionally REST).

> We aim for compatibility with Ethereum tooling (e.g., `web3.py`, `eth_account`) by returning `(r, s, v)` and enforcing EIP-2 (low `s` value).

---

## ✅ Step 1: Confirm SGX Support and Environment Setup

### Hardware

We verified SGX support using the `test-sgx` tool:

- ✅ SGX1 is supported
- ❌ SGX2 is not available (not required for our case)
- ✅ EPC is present and allocated
- ✅ BIOS setting `Software Guard Extensions` is **Enabled**
- ✅ `/dev/isgx` exists after loading the kernel module

### Commands

```bash
# Install dependencies
sudo apt install dkms build-essential
git clone https://github.com/intel/linux-sgx-driver.git
cd linux-sgx-driver
make
sudo make install
```

```bash
# Check SGX device
ls -al /dev/isgx
```

> If `/dev/isgx` is missing, load the module manually:

```bash
sudo modprobe isgx
```

## ✅ Step 2: Build and Run the Intel SGX SDK Sample Project (`SampleEnclave`)

### Objective
Verify that Intel SGX SDK and driver are working correctly by building and running the official `SampleEnclave` application.

### Instructions

1. **Install SGX SDK (Ubuntu 20.04/22.04)**

    ```bash
    sudo apt update
    sudo apt install -y build-essential ocaml automake autoconf libtool wget python3
    wget https://download.01.org/intel-sgx/sgx-linux/2.19/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.19.100.3.bin
    chmod +x sgx_linux_x64_sdk_2.19.100.3.bin
    ./sgx_linux_x64_sdk_2.19.100.3.bin
    ```

    > 📌 When prompted, choose a directory like `$HOME/sgxsdk` and allow installation.

2. **Source the SDK environment**

    ```bash
    source ~/sgxsdk/environment
    ```

3. **Clone the Intel SGX SDK samples and build them**

    ```bash
    git clone https://github.com/intel/linux-sgx.git
    cd linux-sgx/SampleCode/SampleEnclave
    make
    ```

4. **Run the enclave app**

    ```bash
    ./app
    ```

    > You should see output confirming successful interaction with the SGX enclave.

5. **Alternative build**
```
based: https://medium.com/@hasiniwitharana/how-to-set-up-intel-sgx-21227c4ea200
cd linux-sgx
sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl
make preparation
sudo cp external/toolset/ubuntu20.04/* /usr/local/bin
make sdk
make sdk_install_pkg
ls -al /opt/intel/
sudo ./linux/installer/bin/sgx_linux_x64_sdk_2.25.100.3.bin
source /opt/intel/sgxsdk/environment

cd SampleCode/LocalAttestation
make SGX_MODE=SIM
cd bin
./app
succeed to load enclaves.
succeed to establish secure channel.
Succeed to exchange secure message...
Succeed to close Session...

cd linux-sgx/SampleCode/LocalAttestation/
make clean && make SGX_MODE=HW
cd bin/
./app
cd ../../SampleEnclave
make clean && make SGX_MODE=HW
./app 
```
6. **Enclave_private.pem**
```
sudo openssl genrsa -3 -out /opt/intel/sgxsdk/bin/Enclave_private.pem 3072
sudo chmod 666 /opt/intel/sgxsdk/bin/Enclave_private.pem 
```

## Overview

This repository documents the step-by-step process of enabling Intel SGX on a workstation and testing both the Intel SGX SDK and Gramine (formerly Graphene) as potential environments for secure enclaves.

---

## ✅ Current Working Configuration (SGX SDK)

| Component             | Status      | Notes                                |
|----------------------|-------------|--------------------------------------|
| Intel SGX SDK        | ✅ Working   | `isgx` kernel driver is loaded       |
| SampleEnclave (SDK)  | ✅ Working   | Runs in both `SIM` and `HW` modes    |
| LocalAttestation     | ✅ Working   | Secure session established           |
| Gramine in direct mode (`gramine-direct`) | ✅ Working   | But only outside SGX (`SGX=SIM` not fully working) |

---

## ❌ Gramine (intel_sgx driver)

| Component             | Status      | Notes                                                             |
|----------------------|-------------|-------------------------------------------------------------------|
| Gramine SGX mode     | ❌ Not working | Fails due to missing `/dev/sgx/enclave` device                    |
| intel_sgx kernel module | ❌ Not installed | Ubuntu kernel does not ship it by default; requires DKMS or new kernel |
| Switching driver     | ⚠️ Complicated | Involves removing `isgx`, breaking AESM support, rebooting        |

---

## 📌 Decision

For practical development and minimal disruption to the working SGX SDK setup:

**We will continue using the Intel SGX SDK (`isgx` driver)**

### Reasoning:
- SDK works reliably with existing examples.
- No need to patch the kernel or modify boot parameters.
- Gramine requires `intel_sgx` and is not compatible with `isgx`.

---

## Next Steps

We will now explore:
- Running a Python script from within the SGX enclave using the SDK (`system()` or `popen()`).
- Passing signed or encrypted data between the Python side and the enclave.
- Building minimal ECALL/OCALL interface for secure data exchange.

---

## Hardware & Environment

- **CPU:** Intel Xeon E3-1275 v6
- **SGX Capabilities:** SGX1 (✅), SGX2 (❌), Launch Control (❌)
- **SGX Driver:** `isgx` (Intel SGX SDK)
- **OS:** Ubuntu 22.04 LTS
- **SGX SDK Installed:** `/opt/intel/sgxsdk`
- **Kernel Module:** `isgx` is loaded and in use by `aesm_service`

---
## EthSignerEnclave
```
Based: https://github.com/digawp/hello-enclave

cd EthSignerEnclave
make clean
make
```
