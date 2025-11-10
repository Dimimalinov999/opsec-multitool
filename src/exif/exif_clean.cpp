#include "exif_clean.h"
#include <exiv2/exiv2.hpp>
#include <iostream>

void exif_wipe(const std::string& img_path) {
    try {
        auto image = Exiv2::ImageFactory::open(img_path);
        if (!image) {
            std::cerr << "Could not open image.\n";
            return;
        }

        image->readMetadata();
        image->clearMetadata(); // fully wipes exif
        image->writeMetadata();

        std::cout << "EXIF data cleared successfully.\n";
    } catch (Exiv2::Error& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

void exif_clean(const std::string& img_path) {
    try {
        auto image = Exiv2::ImageFactory::open(img_path);
        if (!image) {
            std::cerr << "Could not open image.\n";
            return;
        }

        image->readMetadata();

        // when no exif is found

        Exiv2::ExifData& exifData = image->exifData();
        if (exifData.empty()) {
            std::cout << "No EXIF data found.\n";
            return;
        }

        // selecting keys to remove

        std::vector<std::string> keysToRemove;

        for (const auto& md : exifData) {
            const std::string key = md.key();
            if (key.find("GPS") != std::string::npos ||
                key.find("UserComment") != std::string::npos ||
                key.find("XP") != std::string::npos) {
                keysToRemove.push_back(key);
            }
        }

        // and removes them while keeping technical data, more in the readme

        for (const auto& key : keysToRemove) {
            auto it = exifData.findKey(Exiv2::ExifKey(key));
            if (it != exifData.end())
                exifData.erase(it);
        }

        // writes the new metadata

        image->writeMetadata();
        std::cout << "Sensitive EXIF data removed, technical data preserved.\n";

    } catch (Exiv2::Error& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}