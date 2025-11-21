// openssl 
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "aes/crypto.h"
#include "exif/exif_clean.h"
#include "safedel/safedel.h"
#include "main_header.h"

#include <cstdlib>
#include <ostream>
#include <cstring>
#include <string>
#include <iostream>

void help() { // help text
    std::cout << "Usage:" << std::endl;
    std::cout << "-Use the opsec command follwed by an argument, for example:" << std::endl;
    std::cout << "opsec encrypt aes256 [plain text message in quotes] [encryption key in quotes]" << std::endl;
    std::cout << "-for encryption use opsec encrypt aes256..." << std::endl;
    std::cout << "-for decryption use opsec decrypt aes256..." << std::endl;

}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        std::cerr << "Missing command\n";
        help();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "encrypt" && strcmp(argv[2], "aes256") == 0 && argc >= 5) {
        std::string text = argv[3];
        std::string pass = argv[4];
        std::string b64 = encrypt_aes256_base64(text, pass);
        std::cout << "Base64 encrypted: " << b64 << std::endl;

    } else if (cmd == "decrypt" && strcmp(argv[2], "aes256") == 0 && argc >= 5) {
        std::string b64 = argv[3];
        std::string pass = argv[4];
        std::string decrypted = decrypt_aes256_base64(b64, pass);
        std::cout << "Decrypted text: " << decrypted << std::endl;

    } else if (cmd == "exif" && argc >= 3) {
        if (strcmp(argv[2], "wipe") == 0) {
            std::string img_path = argv[3];
            exif_wipe(img_path);
        }
        if (strcmp(argv[2], "clean") == 0) {
            std::string img_path = argv[3];
            exif_clean(img_path);
        }

    } else if ((cmd == "del" || cmd == "delete") && argc >= 2) {
        std::string del_path = argv[2];
        std::string UnsafePaths[] = {"/", "/boot", "/etc", "/lib", "/lib64", "/bin", "/usr", "/var", "/home", "/root", "/opt", "/proc"};
        int size = sizeof(UnsafePaths) / sizeof(UnsafePaths[0]);

        // failsave, to avoid the user from wiping his main filesystem xD
        if (containsElement(UnsafePaths, size, del_path)) {
            std::cout << "You shouldn't wipe this directory. Aborting.\n";
        } else {
            safedelete(del_path);
            // std::cout << "you just deleted " << del_path << "\n"; // this is for debugging purposes
        }

    /* // TODO: fix this shit.
    } else if (cmd == "encrypt" && strcmp(argv[2], "file") == 0 && argc >= 3) {

        std::string baseFile = argv[2];
        std::string pass = argv[3];
        std::string baseFileOutput = argv[4];
        if (baseFileOutput == "") {
            baseFileOutput = baseFile + ".encrypted";
        }
        encrypt_file_aes256(baseFile, baseFileOutput, pass);
        
    } else if (cmd == "decrypt" && strcmp(argv[2], "file") == 0 && argc >= 3) {

        std::string baseFile = argv[2];
        std::string pass = argv[3];
        std::string baseFileOutput = argv[4]; // output as in the decrypted file :)
        if (baseFileOutput == "") {

        }
        decrypt_file_aes256(baseFile, baseFileOutput, pass);
    */
    } else {
        std::cerr << "Unknown or missing command\n";
        help();
        return 1;
    }

    return 0;
}
