#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <climits>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sys/stat.h>

namespace {
constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;
constexpr unsigned char MAGIC[] = {'C', 'R', 'Y', 'P', 'T', 'O', '1'};

bool readFile(const std::string &path, std::vector<unsigned char> &data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0 || static_cast<unsigned long long>(size) > static_cast<unsigned long long>(INT_MAX)) {
        std::cerr << "File is too large for this single-buffer demonstration (maximum about 2 GB).\n";
        return false;
    }
    file.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty() && !file.read(reinterpret_cast<char *>(data.data()), size)) return false;
    return true;
}

bool writeFile(const std::string &path, const std::vector<unsigned char> &data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    if (!data.empty()) file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(file);
}

bool encryptImage(const std::string &inputPath, const std::string &outputPath, const std::string &keyPath) {
    std::vector<unsigned char> plaintext;
    if (!readFile(inputPath, plaintext)) {
        std::cerr << "Could not read input file: " << inputPath << '\n';
        return false;
    }

    std::vector<unsigned char> key(KEY_SIZE), nonce(NONCE_SIZE);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1 ||
        RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        std::cerr << "Secure random-number generation failed.\n";
        return false;
    }

    EVP_CIPHER_CTX *rawContext = EVP_CIPHER_CTX_new();
    if (!rawContext) return false;
    struct ContextGuard { EVP_CIPHER_CTX *p; ~ContextGuard() { EVP_CIPHER_CTX_free(p); } } guard{rawContext};

    if (EVP_EncryptInit_ex(rawContext, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(rawContext, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(rawContext, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        std::cerr << "AES-GCM encryption initialization failed.\n";
        return false;
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int written = 0, finalWritten = 0;
    unsigned char dummy = 0;
    const unsigned char *plainData = plaintext.empty() ? &dummy : plaintext.data();
    if (EVP_EncryptUpdate(rawContext, ciphertext.data(), &written, plainData,
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(rawContext, ciphertext.data() + written, &finalWritten) != 1) {
        std::cerr << "AES-GCM encryption failed.\n";
        return false;
    }
    ciphertext.resize(static_cast<std::size_t>(written + finalWritten));

    std::vector<unsigned char> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(rawContext, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        std::cerr << "Could not retrieve authentication tag.\n";
        return false;
    }

    std::vector<unsigned char> encrypted;
    encrypted.insert(encrypted.end(), std::begin(MAGIC), std::end(MAGIC));
    encrypted.insert(encrypted.end(), nonce.begin(), nonce.end());
    encrypted.insert(encrypted.end(), ciphertext.begin(), ciphertext.end());
    encrypted.insert(encrypted.end(), tag.begin(), tag.end());

    if (!writeFile(outputPath, encrypted)) {
        std::cerr << "Could not write encrypted file: " << outputPath << '\n';
        return false;
    }
    if (!writeFile(keyPath, key)) {
        std::cerr << "Encrypted file was written, but key file could not be saved.\n";
        return false;
    }
    // Limit access to the generated key file to its owner on POSIX systems.
    chmod(keyPath.c_str(), S_IRUSR | S_IWUSR);
    return true;
}

bool decryptImage(const std::string &inputPath, const std::string &outputPath, const std::string &keyPath) {
    std::vector<unsigned char> encrypted, key;
    if (!readFile(inputPath, encrypted)) {
        std::cerr << "Could not read encrypted file: " << inputPath << '\n';
        return false;
    }
    if (!readFile(keyPath, key) || key.size() != KEY_SIZE) {
        std::cerr << "Key file must exist and contain exactly 32 bytes.\n";
        return false;
    }
    const std::size_t headerSize = sizeof(MAGIC) + NONCE_SIZE;
    if (encrypted.size() < headerSize + TAG_SIZE ||
        !std::equal(std::begin(MAGIC), std::end(MAGIC), encrypted.begin())) {
        std::cerr << "Invalid encrypted-file format.\n";
        return false;
    }

    const unsigned char *nonce = encrypted.data() + sizeof(MAGIC);
    const unsigned char *cipherStart = encrypted.data() + headerSize;
    const std::size_t cipherLength = encrypted.size() - headerSize - TAG_SIZE;
    const unsigned char *tag = encrypted.data() + encrypted.size() - TAG_SIZE;

    EVP_CIPHER_CTX *rawContext = EVP_CIPHER_CTX_new();
    if (!rawContext) return false;
    struct ContextGuard { EVP_CIPHER_CTX *p; ~ContextGuard() { EVP_CIPHER_CTX_free(p); } } guard{rawContext};

    if (EVP_DecryptInit_ex(rawContext, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(rawContext, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(NONCE_SIZE), nullptr) != 1 ||
        EVP_DecryptInit_ex(rawContext, nullptr, nullptr, key.data(), nonce) != 1) {
        std::cerr << "AES-GCM decryption initialization failed.\n";
        return false;
    }

    std::vector<unsigned char> plaintext(cipherLength + 16);
    int written = 0, finalWritten = 0;
    unsigned char dummy = 0;
    unsigned char *plainData = plaintext.empty() ? &dummy : plaintext.data();
    if (EVP_DecryptUpdate(rawContext, plainData, &written, cipherStart,
                          static_cast<int>(cipherLength)) != 1 ||
        EVP_CIPHER_CTX_ctrl(rawContext, EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_SIZE), const_cast<unsigned char *>(tag)) != 1 ||
        EVP_DecryptFinal_ex(rawContext, plainData + written, &finalWritten) != 1) {
        std::cerr << "Authentication failed: wrong key or encrypted data was modified. No output file written.\n";
        return false;
    }
    plaintext.resize(static_cast<std::size_t>(written + finalWritten));
    if (!writeFile(outputPath, plaintext)) {
        std::cerr << "Could not write recovered file: " << outputPath << '\n';
        return false;
    }
    return true;
}
} // namespace

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cout << "AES-256-GCM Image/File Encryption\n\n"
                  << "Usage:\n"
                  << "  ./image encrypt <input-file> <encrypted-file> <key-file>\n"
                  << "  ./image decrypt <encrypted-file> <recovered-file> <key-file>\n\n"
                  << "Example:\n"
                  << "  ./image encrypt photo.jpg encrypted.bin key.bin\n"
                  << "  ./image decrypt encrypted.bin recovered.jpg key.bin\n";
        return 1;
    }

    const std::string operation = argv[1];
    bool success = false;
    if (operation == "encrypt") {
        success = encryptImage(argv[2], argv[3], argv[4]);
        if (success) std::cout << "Encryption successful. Encrypted data: " << argv[3] << "\nKey file: " << argv[4] << '\n';
    } else if (operation == "decrypt") {
        success = decryptImage(argv[2], argv[3], argv[4]);
        if (success) std::cout << "Decryption and authentication successful. Recovered file: " << argv[3] << '\n';
    } else {
        std::cerr << "Operation must be 'encrypt' or 'decrypt'.\n";
        return 1;
    }
    return success ? 0 : 1;
}
