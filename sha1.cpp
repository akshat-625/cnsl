#include <bits/stdc++.h>
#include <openssl/sha.h>
using namespace std;

int main() {
    string message;

    // SHA-1 produces a 20-byte (160-bit) digest.
    unsigned char hash[SHA_DIGEST_LENGTH];

    cout << "Enter message: ";
    getline(cin, message);

    SHA1((unsigned char*)message.c_str(), message.size(), hash);

    cout << "SHA-1 digest: ";

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        cout << hex << setw(2) << setfill('0') << (int)hash[i];

    cout << "\nDigest size: 160 bits\n";
    cout << "Note: SHA-1 is outdated and not recommended for new security systems.\n";
}
