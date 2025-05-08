# EthSignerEnclave

A secure Ethereum transaction signing implementation using Intel SGX enclaves. This project provides a secure environment for generating and managing Ethereum private keys and signing transactions within an Intel SGX enclave.

## Features

- Secure private key generation within SGX enclave
- Transaction signing with secp256k1 implementation
- Hardware-based security using Intel SGX
- Support for both debug and release modes
- Integration with Ethereum's secp256k1 library

## Prerequisites

- Intel SGX SDK (tested with version 2.19)
- Intel SGX PSW (Platform Software)
- GCC/G++ compiler
- Make build system
- Linux operating system with SGX support

## Building

1. Clone the repository:
```bash
git clone https://github.com/yourusername/EthSignerEnclave.git
cd EthSignerEnclave
```

2. Build the project:
```bash
# For debug mode
make SGX_MODE=HW SGX_DEBUG=1

# For release mode
make SGX_MODE=HW
```

## Usage

After building, you can run the application:
```bash
./app
```

The application will:
1. Initialize the SGX enclave
2. Generate a private key
3. Sign a sample transaction
4. Output the results

## Project Structure

- `App/` - Untrusted application code
  - `App.cpp` - Main application entry point
  - `App.h` - Application header
  - `sgx_utils/` - SGX utility functions
- `Enclave/` - Trusted enclave code
  - `Enclave.cpp` - Enclave implementation
  - `Enclave.h` - Enclave header
  - `Enclave.edl` - Enclave Definition Language file
- `lib/` - External libraries
  - `secp256k1/` - Ethereum's secp256k1 implementation

## Security Considerations

- Private keys are generated and stored securely within the SGX enclave
- All cryptographic operations are performed within the enclave
- The enclave provides memory encryption and integrity protection
- Debug mode should only be used for development

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Intel SGX SDK team
- Ethereum Foundation for secp256k1 implementation 
