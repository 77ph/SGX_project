#!/bin/bash

# Компилируем тест RSA шифрования
gcc -g -IEnclave/bearssl/inc -o test Enclave/test.c \
    Enclave/bearssl/src/rsa/*.c \
    Enclave/bearssl/src/int/*.c \
    Enclave/bearssl/src/hash/*.c \
    Enclave/bearssl/src/codec/*.c

# Проверяем успешность компиляции
if [ $? -eq 0 ]; then
    echo "Test compiled successfully"
else
    echo "Compilation failed"
    exit 1
fi 