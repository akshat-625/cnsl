#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

std::vector<unsigned char> xorTransform(const std::vector<unsigned char> &input, const std::string &key) {
    std::vector<unsigned char> output(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        output[i] = static_cast<unsigned char>(input[i] ^ static_cast<unsigned char>(key[i % key.size()]));
    }
    return output;
}

std::string toHex(const std::vector<unsigned char> &data) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : data)
        output << std::setw(2) << static_cast<unsigned int>(byte);
    return output.str();
}

bool fromHex(const std::string &hex, std::vector<unsigned char> &data) {
    if (hex.empty() || hex.size() % 2 != 0) return false;
    data.clear();
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        try {
            std::size_t used = 0;
            unsigned long value = std::stoul(hex.substr(i, 2), &used, 16);
            if (used != 2 || value > 255) return false;
            data.push_back(static_cast<unsigned char>(value));
        } catch (...) {
            return false;
        }
    }
    return true;
}

int main() {
    std::cout << "=== Custom XOR Encryption Demonstration ===\n";
    std::cout << "1. Encrypt text\n2. Decrypt hexadecimal ciphertext\nChoose: ";
    int choice = 0;
    if (!(std::cin >> choice) || (choice != 1 && choice != 2)) {
        std::cerr << "Please choose 1 or 2.\n";
        return 1;
    }
    std::cin.ignore(10000, '\n');

    std::string key;
    std::cout << "Enter secret key (must not be empty): ";
    std::getline(std::cin, key);
    if (key.empty()) {
        std::cerr << "The key cannot be empty.\n";
        return 1;
    }

    if (choice == 1) {
        std::string plaintext;
        std::cout << "Enter plaintext: ";
        std::getline(std::cin, plaintext);
        std::vector<unsigned char> bytes(plaintext.begin(), plaintext.end());
        const auto encrypted = xorTransform(bytes, key);
        std::cout << "Ciphertext (hex): " << toHex(encrypted) << '\n';
        std::cout << "\nFor decryption, run the program again, select option 2, and enter this ciphertext and the same key.\n";
    } else {
        std::string hex;
        std::cout << "Enter ciphertext in hexadecimal: ";
        std::getline(std::cin, hex);
        std::vector<unsigned char> encrypted;
        if (!fromHex(hex, encrypted)) {
            std::cerr << "Invalid hexadecimal ciphertext.\n";
            return 1;
        }
        const auto decrypted = xorTransform(encrypted, key);
        std::cout << "Decrypted text: ";
        for (unsigned char byte : decrypted) std::cout << static_cast<char>(byte);
        std::cout << '\n';
    }

    std::cout << "\nWARNING: Repeating-key XOR is a toy classroom example, not secure file encryption.\n";
    return 0;
}
