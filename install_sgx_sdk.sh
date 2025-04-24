sudo apt update
sudo apt install -y build-essential ocaml automake autoconf libtool wget python3
wget https://download.01.org/intel-sgx/sgx-linux/2.19/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.19.100.3.bin
chmod +x sgx_linux_x64_sdk_2.19.100.3.bin
./sgx_linux_x64_sdk_2.19.100.3.bin
