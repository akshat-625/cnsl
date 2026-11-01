#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

std::vector<int> parseList(const std::string &input, const std::vector<int> &fallback) {
    std::vector<int> values;
    std::stringstream stream(input);
    std::string token;
    while (std::getline(stream, token, ',')) {
        try {
            std::size_t used = 0;
            int value = std::stoi(token, &used);
            while (used < token.size() && std::isspace(static_cast<unsigned char>(token[used]))) ++used;
            if (used != token.size()) throw std::invalid_argument("extra characters");
            values.push_back(value);
        } catch (...) {
            std::cerr << "Invalid list entry: '" << token << "'. Using default values.\n";
            return fallback;
        }
    }
    return values.empty() ? fallback : values;
}

PKeyPtr generateRsaKey(int bits) {
    PKeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
        throw std::runtime_error("RSA key-generation initialization failed.");
    }
    EVP_PKEY *rawKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &rawKey) <= 0 || rawKey == nullptr) {
        throw std::runtime_error("RSA key generation failed.");
    }
    return PKeyPtr(rawKey, EVP_PKEY_free);
}

std::vector<unsigned char> rsaEncrypt(EVP_PKEY *key, const std::vector<unsigned char> &plain) {
    PKeyCtxPtr ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error("RSA encryption initialization failed.");
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outputLength, plain.data(), plain.size()) <= 0)
        throw std::runtime_error("RSA encryption size calculation failed (message may be too large).");

    std::vector<unsigned char> encrypted(outputLength);
    if (EVP_PKEY_encrypt(ctx.get(), encrypted.data(), &outputLength, plain.data(), plain.size()) <= 0)
        throw std::runtime_error("RSA encryption failed.");
    encrypted.resize(outputLength);
    return encrypted;
}

std::vector<unsigned char> rsaDecrypt(EVP_PKEY *key, const std::vector<unsigned char> &cipher) {
    PKeyCtxPtr ctx(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error("RSA decryption initialization failed.");
    }

    std::size_t outputLength = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outputLength, cipher.data(), cipher.size()) <= 0)
        throw std::runtime_error("RSA decryption size calculation failed.");

    std::vector<unsigned char> plain(outputLength);
    if (EVP_PKEY_decrypt(ctx.get(), plain.data(), &outputLength, cipher.data(), cipher.size()) <= 0)
        throw std::runtime_error("RSA decryption failed.");
    plain.resize(outputLength);
    return plain;
}

int readPositiveInt(const std::string &prompt, int defaultValue, int minValue, int maxValue) {
    std::cout << prompt << " [default " << defaultValue << "]: ";
    std::string line;
    std::getline(std::cin, line);
    if (line.empty()) return defaultValue;
    try {
        std::size_t used = 0;
        int value = std::stoi(line, &used);
        if (used != line.size() || value < minValue || value > maxValue)
            throw std::invalid_argument("out of range");
        return value;
    } catch (...) {
        std::cout << "Invalid value; using " << defaultValue << ".\n";
        return defaultValue;
    }
}

int main() {
    try {
        std::cout << "=== RSA Performance Benchmark (RSA-OAEP with SHA-256) ===\n";
        std::cout << "Enter RSA key sizes in bits, comma-separated [default 1024,2048,3072]: ";
        std::string keyLine;
        std::getline(std::cin, keyLine);
        const auto keySizes = parseList(keyLine, {1024, 2048, 3072});

        std::cout << "Enter message sizes in bits, comma-separated [default 64,128,256,512,1024]: ";
        std::string msgLine;
        std::getline(std::cin, msgLine);
        const auto messageSizes = parseList(msgLine, {64, 128, 256, 512, 1024});

        const int keygenRuns = readPositiveInt("Number of key-generation runs", 1, 1, 20);
        const int operationRuns = readPositiveInt("Number of encrypt/decrypt runs per message size", 100, 1, 10000);

        std::cout << "\nOAEP-SHA256 accepts at most (RSA modulus bytes - 66) plaintext bytes.\n";
        std::cout << "A 1024-bit RSA key is included only for classroom comparison and is not secure for new use.\n\n";

        for (int bits : keySizes) {
            if (bits < 1024 || bits > 8192 || bits % 256 != 0) {
                std::cout << "Skipping invalid RSA key size " << bits << " (use 1024..8192 in multiples of 256).\n";
                continue;
            }

            PKeyPtr key(nullptr, EVP_PKEY_free);
            double keygenTotalMs = 0.0;
            for (int i = 0; i < keygenRuns; ++i) {
                const auto start = std::chrono::steady_clock::now();
                key = generateRsaKey(bits);
                const auto stop = std::chrono::steady_clock::now();
                keygenTotalMs += std::chrono::duration<double, std::milli>(stop - start).count();
            }

            const int modulusBytes = EVP_PKEY_get_size(key.get());
            const int maxPlainBytes = modulusBytes - 2 * 32 - 2;
            std::cout << "--- RSA " << bits << " bits ---\n";
            std::cout << "Average key generation time: " << (keygenTotalMs / keygenRuns) << " ms\n";
            std::cout << "Maximum OAEP-SHA256 message size: " << maxPlainBytes << " bytes\n";

            for (int messageBits : messageSizes) {
                if (messageBits <= 0) {
                    std::cout << "  Skipping invalid message size " << messageBits << " bits.\n";
                    continue;
                }
                const std::size_t messageBytes = (static_cast<std::size_t>(messageBits) + 7U) / 8U;
                if (messageBytes > static_cast<std::size_t>(maxPlainBytes)) {
                    std::cout << "  " << messageBits << " bits: skipped (exceeds OAEP limit).\n";
                    continue;
                }

                std::vector<unsigned char> message(messageBytes);
                if (RAND_bytes(message.data(), static_cast<int>(message.size())) != 1)
                    throw std::runtime_error("Random message generation failed.");
                // Force the highest requested bit to 1 so this is genuinely an n-bit test message.
                const unsigned int unusedLeadingBits = static_cast<unsigned int>(messageBytes * 8U - static_cast<std::size_t>(messageBits));
                message[0] &= static_cast<unsigned char>(0xFFU >> unusedLeadingBits);
                message[0] |= static_cast<unsigned char>(1U << (7U - unusedLeadingBits));

                const auto encStart = std::chrono::steady_clock::now();
                std::vector<unsigned char> ciphertext;
                for (int i = 0; i < operationRuns; ++i)
                    ciphertext = rsaEncrypt(key.get(), message);
                const auto encStop = std::chrono::steady_clock::now();

                const auto decStart = std::chrono::steady_clock::now();
                std::vector<unsigned char> recovered;
                for (int i = 0; i < operationRuns; ++i)
                    recovered = rsaDecrypt(key.get(), ciphertext);
                const auto decStop = std::chrono::steady_clock::now();

                if (recovered != message)
                    throw std::runtime_error("Verification failed: decrypted message differs from original.");

                const double encUs = std::chrono::duration<double, std::micro>(encStop - encStart).count() / operationRuns;
                const double decUs = std::chrono::duration<double, std::micro>(decStop - decStart).count() / operationRuns;
                std::cout << "  Message " << messageBits << " bits (" << messageBytes << " bytes): "
                          << "encrypt avg " << encUs << " us, decrypt avg " << decUs << " us; verified\n";
            }
            std::cout << '\n';
        }
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
