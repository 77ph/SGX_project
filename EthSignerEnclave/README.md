# EthSignerEnclave

## Overview
EthSignerEnclave is a secure Ethereum transaction signing system built using Intel SGX technology. It provides a hardware-protected environment for generating and managing Ethereum private keys, as well as signing transactions with enhanced security. The system implements an account pool for efficient key management and supports account recovery through RSA encryption.

## Features
- Secure private key generation using hardware-based entropy
- Transaction signing within SGX enclave
- Account pool management with secure sealing
- Account recovery through RSA-3072 encryption
- Interactive command-line interface
- Test functions for security validation
- Hardware-level protection against timing and side-channel attacks

## Security Features
- Hardware-based entropy generation
- Secure key storage within SGX enclave
- Protected memory for sensitive operations
- Secure state sealing/unsealing
- RSA-3072 encryption for account recovery
- Input validation and sanitization
- Protection against common attack vectors

## Recent Improvements
- Implemented account pool for efficient key management
- Added RSA-3072 based account recovery system
- Enhanced entropy generation and validation
- Added test functions for security validation:
  - Entropy generation testing
  - Save/load cycle testing
  - Transaction signing and verification testing
  - Pool operations testing
- Improved interactive menu with test commands

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
- `load_pool <address>` - Load account to pool
- `unload_pool <address>` - Unload account from pool
- `sign_pool <address> <message>` - Sign message with pool account
- `pool_status` - Show pool status
- `generate_pool` - Generate new account in pool
- `generate_pool_recovery <modulus_hex> <exponent_hex>` - Generate new account with recovery option
- `get_recovery_base64 <address>` - Get base64 encoded recovery file
- `set_log_level <level>` - Set logging level (0=ERROR, 1=WARNING, 2=INFO, 3=DEBUG)
- `run_tests` - Run system validation tests
- `help` - Show help message
- `exit` - Exit the application

## Security Considerations
- All sensitive operations are performed within the SGX enclave
- Private keys never leave the secure environment
- Hardware-based protection against timing and side-channel attacks
- Secure state management with sealing/unsealing
- RSA-3072 encryption for account recovery
- Input validation and sanitization for all operations
- HMAC verification for data integrity

## Future Improvements
See [TODO.en.md](TODO.en.md) for a comprehensive list of planned security improvements.

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
  - `bearssl/` - BearSSL for RSA encryption
- `accounts/` - Account storage directory
- `test_accounts/` - Test account storage directory

## Acknowledgments

- Intel SGX SDK team
- Ethereum Foundation for secp256k1 implementation
- BearSSL team for RSA implementation 
