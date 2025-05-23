# TODO: Security Improvements

## Cryptographic Improvements
- [x] Implement secure deletion of sensitive data (use `sgx_secure_memset` instead of regular `memset`)
- [x] Remove unused nonce functionality (we work on Ledger model where nonce is not needed)

## Key Management
- [x] Add encrypted key backup capability
- [x] Implement key recovery mechanism
- [x] Add key integrity check for each operation (implemented: HMAC verification, address check, data format check, SGX sealed data check)

## Enclave Security
- [ ] Add enclave version check during loading
- [ ] Implement enclave update mechanism
- [ ] Add protection against rollback attacks when saving state
- [ ] Implement enclave compromise detection mechanism

## Audit and Logging
- [x] Add secure logging for critical operations

## State Management
- [x] Implement account pool in memory:
  - [x] Create fixed pool of account slots (e.g., 10 slots)
  - [x] Add commands for loading accounts into specific slots
  - [x] Modify sign_tx command to work with accounts by their address in pool
  - [x] Add commands for viewing pool status (occupied/free slots)
  - [x] Implement account unloading mechanism from pool
  - [x] Add security checks for pool operations

## Hardware Failure Recovery
- [x] Implement optional backup during account generation:
  - [x] Add parameter for user's public RSA key during generation
  - [x] Create additional file with RSA encrypted account data
  - [x] Save original file with SGX encryption
  - [x] Add command to check backup availability
  - [x] Implement recovery mechanism from backup on new hardware
- [ ] Add recovery process documentation

## Input Validation
- [x] Enhance format and length validation of input data
- [x] Add buffer overflow check
- [x] Implement sanitization of all input parameters
- [ ] Add parameter injection check (in server version)

## Access Control
- [ ] Implement operation access control mechanism (in REST API)
- [ ] Add role and permission support (in REST API)
- [ ] Implement access delegation mechanism (in REST API)
- [ ] Add permission check for each operation (in REST API)

## Documentation and Testing
- [x] Add security documentation
- [x] Implement automated security tests
- [ ] Standard mechanism for reporting security issues

## New Priorities
- [ ] Clean up debug information in Enclave.cpp and App.cpp
- [ ] Implement REST API interface
- [ ] Optimize account pool performance (after server version implementation)
- [ ] Improve API documentation
- [ ] Add usage examples
- [ ] Add integration tests 
