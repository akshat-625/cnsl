#include <bits/stdc++.h>
#include <openssl/evp.h>
using namespace std;

int main() {
    string message;

    cout << "Enter message to sign: ";
    getline(cin, message);

    // Generate public and private keys.
    EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY *key = nullptr;

    if (!keyCtx || EVP_PKEY_keygen_init(keyCtx) <= 0 ||
        EVP_PKEY_keygen(keyCtx, &key) <= 0) {
        cout << "Key generation failed.\n";
        return 1;
    }

    EVP_PKEY_CTX_free(keyCtx);

    // Create digital signature using private key.
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sigLen = 0;

    if (!ctx || EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) <= 0 ||
        EVP_DigestSign(ctx, nullptr, &sigLen,
                       (unsigned char*)message.data(), message.size()) <= 0) {
        cout << "Signing setup failed.\n";
        return 1;
    }

    vector<unsigned char> signature(sigLen);

    if (EVP_DigestSign(ctx, signature.data(), &sigLen,
                       (unsigned char*)message.data(), message.size()) <= 0) {
        cout << "Signing failed.\n";
        return 1;
    }

    signature.resize(sigLen);
    EVP_MD_CTX_free(ctx);

    // Extract public key for signature verification.
    unsigned char pubBytes[32];
    size_t pubLen = sizeof(pubBytes);

    if (EVP_PKEY_get_raw_public_key(key, pubBytes, &pubLen) <= 0) {
        cout << "Public key extraction failed.\n";
        return 1;
    }

    EVP_PKEY *pubKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pubBytes, pubLen
    );

    if (!pubKey) {
        cout << "Public key creation failed.\n";
        return 1;
    }

    // Verify signature using the public key.
    ctx = EVP_MD_CTX_new();

    if (!ctx || EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pubKey) <= 0) {
        cout << "Verification setup failed.\n";
        return 1;
    }

    int ok = EVP_DigestVerify(
        ctx, signature.data(), signature.size(),
        (unsigned char*)message.data(), message.size()
    );

    cout << "Signature verification: "
         << (ok == 1 ? "Successful" : "Failed") << "\n";

    // Change message to show that verification fails.
    string changed = message + " changed";

    EVP_MD_CTX_reset(ctx);

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pubKey) <= 0) {
        cout << "Verification setup failed.\n";
        return 1;
    }

    int changedOK = EVP_DigestVerify(
        ctx, signature.data(), signature.size(),
        (unsigned char*)changed.data(), changed.size()
    );

    cout << "Modified message: "
         << (changedOK == 1 ? "Accepted" : "Rejected") << "\n";

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    EVP_PKEY_free(key);
}
