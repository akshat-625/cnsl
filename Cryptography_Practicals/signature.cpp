#include <openssl/evp.h>

#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using PKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

void printHex(const std::vector<unsigned char> &data) {
    for (unsigned char byte : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    std::cout << std::dec << '\n';
}

int main() {
    std::cout << "=== Digital Signature (Ed25519) ===\n";
    std::string message;
    std::cout << "Enter message to sign: ";
    std::getline(std::cin, message);

    PKeyCtxPtr keygenContext(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    if (!keygenContext || EVP_PKEY_keygen_init(keygenContext.get()) <= 0) {
        std::cerr << "Ed25519 key-generation initialization failed.\n";
        return 1;
    }
    EVP_PKEY *rawPrivateKey = nullptr;
    if (EVP_PKEY_keygen(keygenContext.get(), &rawPrivateKey) <= 0 || rawPrivateKey == nullptr) {
        std::cerr << "Ed25519 key generation failed.\n";
        return 1;
    }
    PKeyPtr privateKey(rawPrivateKey, EVP_PKEY_free);

    std::size_t publicKeyLength = 0;
    if (EVP_PKEY_get_raw_public_key(privateKey.get(), nullptr, &publicKeyLength) <= 0) {
        std::cerr << "Could not determine public-key length.\n";
        return 1;
    }
    std::vector<unsigned char> publicKeyBytes(publicKeyLength);
    if (EVP_PKEY_get_raw_public_key(privateKey.get(), publicKeyBytes.data(), &publicKeyLength) <= 0) {
        std::cerr << "Could not extract public key.\n";
        return 1;
    }
    publicKeyBytes.resize(publicKeyLength);

    PKeyPtr publicKey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  publicKeyBytes.data(), publicKeyBytes.size()), EVP_PKEY_free);
    if (!publicKey) {
        std::cerr << "Could not create public-key object.\n";
        return 1;
    }

    MdCtxPtr signContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!signContext || EVP_DigestSignInit(signContext.get(), nullptr, nullptr, nullptr, privateKey.get()) <= 0) {
        std::cerr << "Signature initialization failed.\n";
        return 1;
    }

    std::size_t signatureLength = 0;
    if (EVP_DigestSign(signContext.get(), nullptr, &signatureLength,
                       reinterpret_cast<const unsigned char *>(message.data()), message.size()) <= 0) {
        std::cerr << "Could not determine signature length.\n";
        return 1;
    }
    std::vector<unsigned char> signature(signatureLength);
    if (EVP_DigestSign(signContext.get(), signature.data(), &signatureLength,
                       reinterpret_cast<const unsigned char *>(message.data()), message.size()) <= 0) {
        std::cerr << "Signing failed.\n";
        return 1;
    }
    signature.resize(signatureLength);

    std::cout << "Public key (hex): ";
    printHex(publicKeyBytes);
    std::cout << "Signature (hex): ";
    printHex(signature);

    MdCtxPtr verifyContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!verifyContext || EVP_DigestVerifyInit(verifyContext.get(), nullptr, nullptr, nullptr, publicKey.get()) <= 0) {
        std::cerr << "Signature verification initialization failed.\n";
        return 1;
    }
    const int originalResult = EVP_DigestVerify(
        verifyContext.get(), signature.data(), signature.size(),
        reinterpret_cast<const unsigned char *>(message.data()), message.size());
    std::cout << "Original message: " << (originalResult == 1 ? "SIGNATURE VERIFIED" : "VERIFICATION FAILED") << '\n';

    std::string modifiedMessage;
    std::cout << "Enter a message to test (press Enter to modify the original automatically): ";
    std::getline(std::cin, modifiedMessage);
    if (modifiedMessage.empty()) modifiedMessage = message + " [modified]";

    MdCtxPtr modifiedVerifyContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!modifiedVerifyContext || EVP_DigestVerifyInit(modifiedVerifyContext.get(), nullptr, nullptr, nullptr, publicKey.get()) <= 0) {
        std::cerr << "Modified-message verification initialization failed.\n";
        return 1;
    }
    const int modifiedResult = EVP_DigestVerify(
        modifiedVerifyContext.get(), signature.data(), signature.size(),
        reinterpret_cast<const unsigned char *>(modifiedMessage.data()), modifiedMessage.size());
    std::cout << "Test message: " << (modifiedResult == 1 ? "SIGNATURE VERIFIED" : "SIGNATURE REJECTED") << '\n';
    std::cout << "\nNote: This run creates a temporary key pair. A real system must protect private keys and authenticate public-key ownership.\n";
    return originalResult == 1 ? 0 : 1;
}
