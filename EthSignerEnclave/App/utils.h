#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

// Base64 декодирование
std::vector<uint8_t> base64_decode(const std::string& encoded);

// Конвертация байтов в hex строку
std::string bytes_to_hex(const std::vector<uint8_t>& data);

#endif // UTILS_H 