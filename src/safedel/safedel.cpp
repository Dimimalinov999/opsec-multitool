#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>

void safedelete(const std::string& del_path) {
    // failsave 2, to (once again) avoid the user from wiping his main filesystem xD
    if (del_path == "/") {
        std::cout << "You shouldn't wipe your root filesystem. Aborting.\n";
    } else {
        if (!std::filesystem::exists(del_path)) {
            std::cerr << "File doesn't exist.\n";
        }


        // finding file size
        std::uintmax_t file_size = std::filesystem::file_size(del_path);
        std::cout << "file size is " << file_size << " bytes\n";

        std::fstream file(del_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Unable to open file.\n";
        }

        const std::size_t chunk_size = 1024 * 1024; // 1mb buffer
        std::vector<char> buffer(chunk_size, 0);

        // writing the zeros
        std::uintmax_t written = 0;
        while (written < file_size) {
            std::size_t to_write = std::min<std::uintmax_t>(chunk_size, file_size - written);
            file.write(buffer.data(), to_write);
            if (!file) {
                std::cerr << "Error while writing.\n";
            }
            written += to_write;
        }

        file.close();

        // deleting the file
        std::filesystem::remove(del_path);
        std::cout << "File has been deleted.\n";
    }
}