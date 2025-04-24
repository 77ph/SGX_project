sudo apt install git curl build-essential python3 python3-pip libssl-dev \
     libprotobuf-dev protobuf-compiler libcurl4-openssl-dev \
     libelf-dev libtool automake autoconf

sudo apt install libsgx-urts libsgx-enclave-common

sudo curl -fsSLo /etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg https://packages.gramineproject.io/gramine-keyring-$(lsb_release -sc).gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/gramine-keyring-$(lsb_release -sc).gpg] https://packages.gramineproject.io/ $(lsb_release -sc) main" \
| sudo tee /etc/apt/sources.list.d/gramine.list

sudo apt-get update
sudo apt-get install gramine

git clone --depth 1  https://github.com/gramineproject/gramine.git


