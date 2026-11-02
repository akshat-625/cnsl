#define OPENSSL_SUPPRESS_DEPRECATED
#include <bits/stdc++.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
using namespace std;
using namespace chrono;

// Generate RSA key pair
RSA* makeKey(int bits) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    if (!rsa || !e) {
        RSA_free(rsa);
        BN_free(e);
        return nullptr;
    }

    BN_set_word(e, RSA_F4); // Public exponent 65537

    if (RSA_generate_key_ex(rsa, bits, e, nullptr) != 1) {
        RSA_free(rsa);
        rsa = nullptr;
    }

    BN_free(e);
    return rsa;
}

int main() {
    vector<int> keySizes = {1024, 2048, 3072};
    vector<int> messageSizes = {64, 128, 256, 512, 1024};

    int rounds;

    cout << "Enter number of encryption/decryption rounds: ";
    cin >> rounds;

    if (!cin || rounds < 1 || rounds > 10000) {
        cout << "Enter rounds between 1 and 10000.\n";
        return 1;
    }

    for (int bits : keySizes) {
        auto start = steady_clock::now();

        RSA *rsa = makeKey(bits);

        auto stop = steady_clock::now();

        if (!rsa) {
            cout << "Key generation failed.\n";
            continue;
        }

        double keyTime =
            duration<double, milli>(stop - start).count();

        cout << "\nRSA key size: " << bits << " bits\n";
        cout << "Key generation time: " << keyTime << " ms\n";

        int maxBytes = RSA_size(rsa) - 42;
        // OAEP with SHA-1 uses 42 bytes of padding overhead.

        for (int msgBits : messageSizes) {
            int bytes = msgBits / 8;

            if (bytes > maxBytes) {
                cout << msgBits << "-bit message: Too large for this key.\n";
                continue;
            }

            vector<unsigned char> msg(bytes);
            vector<unsigned char> cipher(RSA_size(rsa));
            vector<unsigned char> recovered(RSA_size(rsa));

            RAND_bytes(msg.data(), bytes);
            msg[0] |= 0x80; // Ensure requested message bit length

            // Measure encryption
            auto encStart = steady_clock::now();

            int cipherLen = 0;

            for (int i = 0; i < rounds; i++)
                cipherLen = RSA_public_encrypt(
                    bytes, msg.data(), cipher.data(),
                    rsa, RSA_PKCS1_OAEP_PADDING
                );

            auto encStop = steady_clock::now();

            if (cipherLen == -1) {
                cout << "Encryption failed.\n";
                continue;
            }

            // Measure decryption
            auto decStart = steady_clock::now();

            int plainLen = 0;

            for (int i = 0; i < rounds; i++)
                plainLen = RSA_private_decrypt(
                    cipherLen, cipher.data(), recovered.data(),
                    rsa, RSA_PKCS1_OAEP_PADDING
                );

            auto decStop = steady_clock::now();

            bool correct = plainLen == bytes &&
                equal(msg.begin(), msg.end(), recovered.begin());

            double encTime =
                duration<double, micro>(encStop - encStart).count() / rounds;

            double decTime =
                duration<double, micro>(decStop - decStart).count() / rounds;

            cout << msgBits << "-bit message:\n";
            cout << "Encryption time = " << encTime << " us\n";
            cout << "Decryption time = " << decTime << " us\n";
            cout << "Verified = " << (correct ? "Yes" : "No") << "\n";
        }

        RSA_free(rsa);
    }

    cout << "\n1024-bit RSA is included only for comparison, not real security.\n";
}
