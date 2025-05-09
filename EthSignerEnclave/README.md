# EthSignerEnclave

## Overview
EthSignerEnclave is a secure Ethereum transaction signing system built using Intel SGX technology. It provides a hardware-protected environment for generating and managing Ethereum private keys, as well as signing transactions with enhanced security.

## Features
- Secure private key generation using hardware-based entropy
- Transaction signing within SGX enclave
- Account state management with secure sealing
- Interactive command-line interface
- Test functions for security validation
- Hardware-level protection against timing and side-channel attacks

## Security Features
- Hardware-based entropy generation
- Secure key storage within SGX enclave
- Protected memory for sensitive operations
- Secure state sealing/unsealing
- Input validation and sanitization
- Protection against common attack vectors

## Recent Improvements
- Enhanced entropy generation and validation
- Added test functions for security validation:
  - Entropy generation testing
  - Save/load cycle testing
  - Transaction signing and verification testing
- Improved interactive menu with test commands
- Added comprehensive security TODO list

## Building and Running
1. Install Intel SGX SDK and dependencies
2. Build the project:
```bash
make clean && make SGX_MODE=HW SGX_DEBUG=1
```
3. Run the application:
```bash
./app
```

## Available Commands
- `generate_account` - Generate a new Ethereum account
- `sign_tx 0000000000000000000000000000000000000000000000000000000000000001` - Sign a transaction with the stored private key
- `save_account_state` - Save the current account state
- `load_account_state` - Load a previously saved account state
- `test_key_strength` - Test private key generation and strength
- `test_entropy` - Test entropy generation
- `test_save_load` - Test the save/load cycle
- `test_sign_verify` - Test transaction signing and verification

## Security Considerations
- All sensitive operations are performed within the SGX enclave
- Private keys never leave the secure environment
- Hardware-based protection against timing and side-channel attacks
- Secure state management with sealing/unsealing
- Input validation and sanitization for all operations

## Future Improvements
See [TODO.md](TODO.md) for a comprehensive list of planned security improvements.

## Requirements
- Intel SGX-capable processor
- Intel SGX SDK
- Linux operating system
- C++ compiler with C++11 support

## License
[Specify your license here]

## Contributing
[Add contribution guidelines if applicable]

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

## Acknowledgments

- Intel SGX SDK team
- Ethereum Foundation for secp256k1 implementation 
