#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <fstream>

// ENCRYPTION
void encrypt_file_aes256(const std::string& input_path, const std::string& output_path, const std::string& passphrase) {
    const int key_len = 32;
    const int iv_len = 16;
    const int salt_len = 8;
    const int iterations = 100000;
    const size_t BUF_SIZE = 4096; // chunk size for input output (i/o)

    // setting up the files
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file.is_open()) {
        throw std::runtime_error("Failed to open input file: " + input_path);
    }

    std::ofstream output_file(output_path, std::ios::binary | std::ios::trunc);
    if (!output_file.is_open()) {
        throw std::runtime_error("Failed to open output file for writing: " + output_path);
    }

    // generating salt and IV
    unsigned char salt[salt_len];
    if (RAND_bytes(salt, salt_len) != 1) throw std::runtime_error("RAND_bytes failed for salt");

    unsigned char iv[iv_len];
    if (RAND_bytes(iv, iv_len) != 1) throw std::runtime_error("RAND_bytes failed for IV");

    // derive key
    std::vector<unsigned char> key(key_len);
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), (int)passphrase.size(),
                          salt, salt_len, iterations, EVP_sha256(),
                          key_len, key.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }

    // 4. Write Header (Salted__ + Salt + IV)
    const std::string header = "Salted__";
    output_file.write(header.data(), header.size());
    output_file.write(reinterpret_cast<const char*>(salt), salt_len);
    output_file.write(reinterpret_cast<const char*>(iv), iv_len);

    if (output_file.fail()) {
        throw std::runtime_error("Failed to write header to output file.");
    }

    // enc context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    // enc chunks
    std::vector<char> in_buf(BUF_SIZE);
    std::vector<char> out_buf(BUF_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen;

    while (input_file.read(in_buf.data(), BUF_SIZE)) {
        size_t bytes_read = input_file.gcount();

        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen,
                              reinterpret_cast<const unsigned char*>(in_buf.data()), (int)bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed during file encryption");
        }
        output_file.write(out_buf.data(), outlen);
        if (output_file.fail()) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to write encrypted data chunk.");
        }
    }

    // handle the last, potentially partial, read
    size_t bytes_read = input_file.gcount();
    if (bytes_read > 0) {
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen,
                              reinterpret_cast<const unsigned char*>(in_buf.data()), (int)bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed on final chunk");
        }
        output_file.write(out_buf.data(), outlen);
        if (output_file.fail()) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to write final encrypted data chunk.");
        }
    }

    // padding
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    output_file.write(out_buf.data(), outlen);

    // cleanup, fuck memory leaks
    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();
    if (output_file.fail()) {
        throw std::runtime_error("Final file stream status check failed.");
    }
}

// DECRYPTION
void decrypt_file_aes256(const std::string& input_path, const std::string& output_path, const std::string& passphrase) {
    const int key_len = 32;
    const int iv_len = 16;
    const int salt_len = 8;
    const int iterations = 100000;
    const size_t BUF_SIZE = 4096; // chunk size once again

    // setup
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file.is_open()) {
        throw std::runtime_error("Failed to open input file: " + input_path);
    }

    std::ofstream output_file(output_path, std::ios::binary | std::ios::trunc);
    if (!output_file.is_open()) {
        throw std::runtime_error("Failed to open output file for writing: " + output_path);
    }

    // reading iv and salt
    char header_buf[8];
    unsigned char salt[salt_len];
    unsigned char iv[iv_len];

    input_file.read(header_buf, 8);
    if (input_file.gcount() != 8 || std::string(header_buf, 8) != "Salted__") {
        throw std::runtime_error("Input file missing or has corrupted 'Salted__' header.");
    }

    input_file.read(reinterpret_cast<char*>(salt), salt_len);
    if (input_file.gcount() != salt_len) {
        throw std::runtime_error("Input file too short or salt corrupted.");
    }

    input_file.read(reinterpret_cast<char*>(iv), iv_len);
    if (input_file.gcount() != iv_len) {
        throw std::runtime_error("Input file too short or IV corrupted.");
    }

    // deriving again
    std::vector<unsigned char> key(key_len);
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), (int)passphrase.size(),
                          salt, salt_len, iterations, EVP_sha256(),
                          key_len, key.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }

    // context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    // decrypt chunks
    std::vector<char> in_buf(BUF_SIZE);
    std::vector<char> out_buf(BUF_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen;

    while (input_file.read(in_buf.data(), BUF_SIZE)) {
        size_t bytes_read = input_file.gcount();

        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen,
                              reinterpret_cast<const unsigned char*>(in_buf.data()), (int)bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed. Wrong password or corrupted data.");
        }
        output_file.write(out_buf.data(), outlen);
        if (output_file.fail()) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to write decrypted data chunk.");
        }
    }
    
    // handle the last, potentially partial, read
    size_t bytes_read = input_file.gcount();
    if (bytes_read > 0) {
        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen,
                              reinterpret_cast<const unsigned char*>(in_buf.data()), (int)bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed on final chunk. Wrong password or corrupted data.");
        }
        output_file.write(out_buf.data(), outlen);
        if (output_file.fail()) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to write final decrypted data chunk.");
        }
    }

    // check padding
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(out_buf.data()), &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        // this is the most likely place for a wrong password or bad padding/tampering error
        throw std::runtime_error("EVP_DecryptFinal_ex failed. Wrong password or corrupted data.");
    }
    output_file.write(out_buf.data(), outlen);

    // cleanup
    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();
    if (output_file.fail()) {
        throw std::runtime_error("Final file stream status check failed.");
    }
}