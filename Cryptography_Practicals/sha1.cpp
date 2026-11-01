#include <openssl/evp.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

bool calculateSha1(const std::string &message, std::vector<unsigned char> &digest) {
    digest.resize(EVP_MD_size(EVP_sha1()));
    unsigned int digestLength = 0;
    if (EVP_Digest(message.data(), message.size(), digest.data(), &digestLength, EVP_sha1(), nullptr) != 1)
        return false;
    digest.resize(digestLength);
    return true;
}

void printHex(const std::vector<unsigned char> &data) {
    for (unsigned char byte : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(byte);
    std::cout << std::dec << '\n';
}

int main() {
    std::cout << "=== SHA-1 Message Digest ===\n";
    std::string message;
    std::cout << "Enter a message: ";
    std::getline(std::cin, message);

    std::vector<unsigned char> digest;
    if (!calculateSha1(message, digest)) {
        std::cerr << "SHA-1 calculation failed.\n";
        return 1;
    }

    std::cout << "SHA-1 digest: ";
    printHex(digest);
    std::cout << "Digest length: " << digest.size() << " bytes (" << digest.size() * 8 << " bits)\n";

    std::string changed = message;
    if (!changed.empty()) changed[0] = (changed[0] == 'A') ? 'B' : 'A';
    else changed = "A";

    std::vector<unsigned char> changedDigest;
    if (!calculateSha1(changed, changedDigest)) {
        std::cerr << "SHA-1 calculation for modified text failed.\n";
        return 1;
    }
    std::cout << "Modified message: " << changed << '\n';
    std::cout << "Modified digest:  ";
    printHex(changedDigest);
    std::cout << "\nNote: SHA-1 is collision-broken and should not be used for new security designs.\n";
    return 0;
}
