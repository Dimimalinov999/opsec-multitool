#pragma once
#include <string>

// AES-256-CBC with base64
std::string encrypt_aes256_base64(const std::string& plaintext, const std::string& passphrase);
std::string decrypt_aes256_base64(const std::string& b64ciphertext, const std::string& passphrase);

// base64 utility
std::string base64_encode(const unsigned char* data, size_t len);
std::string base64_decode(const std::string& input);

// file crypting
// std::string encrypt_file_aes256(const std::string& input_path, const std::string& output_path, const std::string& passphrase);
// std::string decrypt_file_aes256(const std::string& input_path, const std::string& output_path, const std::string& passphrase);
