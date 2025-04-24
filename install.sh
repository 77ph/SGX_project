sudo apt install dkms build-essential
# Добавим репо Intel
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx.gpg
echo "deb [signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt update

# Установим SGX SDK и runtime
sudo apt install libsgx-enclave-common libsgx-urts sgx-aesm-service

