sudo apt update
sudo apt install -y dkms build-essential git linux-headers-$(uname -r)
git clone https://github.com/intel/linux-sgx-driver.git
cd linux-sgx-driver
make
sudo make install
sudo modprobe isgx
ls /dev/isgx

