// openssl 
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "aes/crypto.h"

#include <cstdlib>
#include <ostream>
#include <vector>
#include <cstring>
#include <string>
#include <iostream>

void help() { // help text
    std::cout << "Usage:" << std::endl;
    std::cout << "Use the opsec command follwed by an argument, for example:" << std::endl;
    std::cout << "opsec encrypt aes256 [plain text message in quotes] [encryption key in quotes]" << std::endl;
    std::cout << "for encryption use opsec encrypt aes256..." << std::endl;
    std::cout << "for decryption use opsec decrypt aes256..." << std::endl;

}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Missing command\n";
        help();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "encrypt" && argc >= 5) {
        std::string text = argv[3];
        std::string pass = argv[4];
        std::string b64 = encrypt_aes256_base64(text, pass);
        std::cout << "Base64 encrypted: " << b64 << std::endl;

    } else if (cmd == "decrypt" && argc >= 5) {
        std::string b64 = argv[3];
        std::string pass = argv[4];
        std::string decrypted = decrypt_aes256_base64(b64, pass);
        std::cout << "Decrypted text: " << decrypted << std::endl;

    } else {
        std::cerr << "Unknown or missing command\n";
        help();
        return 1;
    }

    return 0;
}
