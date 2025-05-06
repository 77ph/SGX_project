#include <stdint.h>

extern "C" {
    struct sgx_metadata_t {
        uint32_t namesz;
        uint32_t descsz;
        uint32_t type;
        char name[13];  // Increased size to accommodate null terminator
        uint8_t desc[512];  // Increased size for config content
    } __attribute__((aligned(4)));

    #define SECTION_ATTRIBUTE __attribute__((section(".note.sgxmeta"), aligned(4), used))
    #define NOTE_ATTRIBUTE __attribute__((aligned(4)))

    SECTION_ATTRIBUTE NOTE_ATTRIBUTE const sgx_metadata_t sgx_metadata = {
        .namesz = 13,  // Updated to include null terminator
        .descsz = 512,  // Size of config content
        .type = 1,
        .name = {'s', 'g', 'x', '_', 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', '\0'},  // Added null terminator
        .desc = {
            '<', '?', 'x', 'm', 'l', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n', '=', '"', '1', '.', '0', '"', '?', '>', '\n',
            '<', 'E', 'n', 'c', 'l', 'a', 'v', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'u', 'r', 'a', 't', 'i', 'o', 'n', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'P', 'r', 'o', 'd', 'I', 'D', '>', '0', '<', '/', 'P', 'r', 'o', 'd', 'I', 'D', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'I', 'S', 'V', 'S', 'V', 'N', '>', '0', '<', '/', 'I', 'S', 'V', 'S', 'V', 'N', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'S', 't', 'a', 'c', 'k', 'M', 'a', 'x', 'S', 'i', 'z', 'e', '>', '0', 'x', '4', '0', '0', '0', '0', '<', '/', 'S', 't', 'a', 'c', 'k', 'M', 'a', 'x', 'S', 'i', 'z', 'e', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'H', 'e', 'a', 'p', 'M', 'a', 'x', 'S', 'i', 'z', 'e', '>', '0', 'x', '1', '0', '0', '0', '0', '0', '<', '/', 'H', 'e', 'a', 'p', 'M', 'a', 'x', 'S', 'i', 'z', 'e', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'T', 'C', 'S', 'N', 'u', 'm', '>', '1', '0', '<', '/', 'T', 'C', 'S', 'N', 'u', 'm', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'T', 'C', 'S', 'P', 'o', 'l', 'i', 'c', 'y', '>', '1', '<', '/', 'T', 'C', 'S', 'P', 'o', 'l', 'i', 'c', 'y', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'D', 'i', 's', 'a', 'b', 'l', 'e', 'D', 'e', 'b', 'u', 'g', '>', '0', '<', '/', 'D', 'i', 's', 'a', 'b', 'l', 'e', 'D', 'e', 'b', 'u', 'g', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'M', 'i', 's', 'c', 'S', 'e', 'l', 'e', 'c', 't', '>', '0', '<', '/', 'M', 'i', 's', 'c', 'S', 'e', 'l', 'e', 'c', 't', '>', '\n',
            ' ', ' ', ' ', ' ', '<', 'M', 'i', 's', 'c', 'M', 'a', 's', 'k', '>', '0', 'x', 'F', 'F', 'F', 'F', 'F', 'F', 'F', 'F', '<', '/', 'M', 'i', 's', 'c', 'M', 'a', 's', 'k', '>', '\n',
            '<', '/', 'E', 'n', 'c', 'l', 'a', 'v', 'e', 'C', 'o', 'n', 'f', 'i', 'g', 'u', 'r', 'a', 't', 'i', 'o', 'n', '>', '\n',
            0  // Null terminator
        }
    };
} 
