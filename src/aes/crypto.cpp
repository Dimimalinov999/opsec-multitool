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

// base64 encoding
std::string base64_encode(const unsigned char* data, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, data, (int)len);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string ret(bptr->data, bptr->length);

    BIO_free_all(b64);
    return ret;
}

// base64 decoding
std::string base64_decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), (int)input.size());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    std::vector<unsigned char> output(input.size());
    int outlen = BIO_read(b64, output.data(), (int)input.size());
    if (outlen <= 0) outlen = 0;

    BIO_free_all(b64);
    return std::string(reinterpret_cast<char*>(output.data()), outlen);
}

// Encrypt AES-256-CBC -> base64
std::string encrypt_aes256_base64(const std::string& plaintext, const std::string& passphrase) {
    const int key_len = 32;
    const int iv_len = 16;
    const int salt_len = 8;
    const int iterations = 100000;

    unsigned char salt[salt_len];
    if (RAND_bytes(salt, salt_len) != 1) throw std::runtime_error("RAND_bytes failed");

    std::vector<unsigned char> key(key_len);
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), (int)passphrase.size(),
                          salt, salt_len, iterations, EVP_sha256(),
                          key_len, key.data()) != 1)
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");

    unsigned char iv[iv_len];
    if (RAND_bytes(iv, iv_len) != 1) throw std::runtime_error("RAND_bytes for IV failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int outlen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);

    std::string header = "Salted__";
    std::vector<unsigned char> out;
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), salt, salt + salt_len);
    out.insert(out.end(), iv, iv + iv_len);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());

    return base64_encode(out.data(), out.size());
}

// Decrypt base64 -> AES-256-CBC
std::string decrypt_aes256_base64(const std::string& b64ciphertext, const std::string& passphrase) {
    const int key_len = 32;
    const int iv_len = 16;
    const int salt_len = 8;
    const int iterations = 100000;

    std::string data = base64_decode(b64ciphertext);
    if (data.size() < 8 + salt_len + iv_len) throw std::runtime_error("Ciphertext too short");
    if (data.substr(0, 8) != "Salted__") throw std::runtime_error("Missing Salted__ header");

    const unsigned char* salt = reinterpret_cast<const unsigned char*>(data.data() + 8);
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(data.data() + 8 + salt_len);
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(data.data() + 8 + salt_len + iv_len);
    size_t ciphertext_len = data.size() - (8 + salt_len + iv_len);

    std::vector<unsigned char> key(key_len);
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), (int)passphrase.size(),
                          salt, salt_len, iterations, EVP_sha256(),
                          key_len, key.data()) != 1)
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int outlen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed. Wrong password or corrupted data");
    }
    plaintext.resize(outlen1 + outlen2);

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}
