#include <cstring>
#include <string>
#include "main_header.h"


bool containsElement(std::string arr[], int size, std::string target) {
    for (int i = 0; i < size; ++i) {
        if (arr[i] == target) {
            return true; // element found
        }
    }
    return false; // element not found
}