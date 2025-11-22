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

void help(int whatHelp) { // help text
    if (whatHelp == 1) {
      std::cout << "Help:\n";
      std::cout << "\e[1mbold" << "Encrypting:" << "\e[0m" << std::endl;
      std::cout << std::endl;
      std::cout << "opsec encrypt [plain text in quotes] [encryption key in quotes]\n";
      std::cout << "\e[1mbold" << "Decrypting:" << "\e[0m" << std::endl;
      std::cout << std::endl;
      std::cout << "opsec decrypt [plain text in quotes] [encryption key in quotes]\n";
      std::cout << "\e[1mbold" << "EXIF tools:" << "\e[0m" << std::endl;
      std::cout << std::endl;
      std::cout << "opsec exif clean [file path]\n" << "or\n";
      std::cout << "opsec exif wipe [file path]\n";
      std::cout << "Note: clean removes only sensitive metadata, while wipe removes all exif metadata.\n";
      std::cout << "\e[1mbold" << "SafeDelete:" << "\e[0m" << std::endl;



      
    }
    else {
      std::cout << "Usage:" << std::endl;
      std::cout << "-Use the opsec command follwed by an argument, for example:" << std::endl;
      std::cout << "opsec encrypt [plain text message in quotes] [encryption key in quotes]" << std::endl;
      std::cout << "-for encryption use opsec encrypt ..." << std::endl;
      std::cout << "-for decryption use opsec decrypt ..." << std::endl;
    }

}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        std::cerr << "Missing command\n";
        help(0);
        return 1;
    }

    std::string cmd = argv[1];

    if ((cmd == "encrypt" || cmd == "enc") && argc >= 4) {
        std::string text = argv[2];
        std::string pass = argv[3];
        std::string b64 = encrypt_aes256_base64(text, pass);
        std::cout << "Base64 encrypted: " << b64 << std::endl;

    } else if ((cmd == "decrypt" || cmd == "dec") && argc >= 4) {
        std::string b64 = argv[2];
        std::string pass = argv[3];
        std::string decrypted = decrypt_aes256_base64(b64, pass);
        std::cout << "Decrypted text: " << decrypted << std::endl;

    } else if (cmd == "help" && argc >= 1) {
      
      help(1);

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
        help(0);
        return 1;
    }

    return 0;
}
