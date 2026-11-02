#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
using namespace std;

// Read and write image files in binary mode.
bool readFile(string name, vector<unsigned char>& data) {
    ifstream in(name, ios::binary);
    if (!in) return false;

    data.assign(istreambuf_iterator<char>(in), {});
    return true;
}

bool writeFile(string name, const vector<unsigned char>& data) {
    ofstream out(name, ios::binary);
    if (!out) return false;

    out.write((char*)data.data(), data.size());
    return (bool)out;
}

int main() {
    int choice;
    string input, output, keyFile;

    const int KEY = 32, NONCE = 12, TAG = 16;
    // AES-256 uses a 32-byte key; GCM uses a nonce and authentication tag.

    cout << "1. Encrypt image/file\n2. Decrypt image/file\nChoose: ";
    cin >> choice;

    cout << "Input filename: ";
    cin >> input;

    cout << "Output filename: ";
    cin >> output;

    cout << "Key filename: ";
    cin >> keyFile;

    vector<unsigned char> data, key(KEY), nonce(NONCE), result;

    if (!readFile(input, data)) {
        cout << "Cannot read input file.\n";
        return 1;
    }

    if (data.size() > INT_MAX) {
        cout << "File is too large for this simple program.\n";
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        cout << "Encryption context creation failed.\n";
        return 1;
    }

    int len = 0, total = 0;

    if (choice == 1) {
        // Generate random secret key and nonce.
        if (RAND_bytes(key.data(), KEY) != 1 ||
            RAND_bytes(nonce.data(), NONCE) != 1) {
            cout << "Random generation failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                              nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                NONCE, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                              key.data(), nonce.data()) != 1) {
            cout << "Encryption setup failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        vector<unsigned char> cipher(data.size() + 16);

        if (EVP_EncryptUpdate(ctx, cipher.data(), &len,
                              data.data(), data.size()) != 1) {
            cout << "Encryption failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        total = len;

        if (EVP_EncryptFinal_ex(ctx, cipher.data() + total, &len) != 1) {
            cout << "Encryption finalization failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        total += len;
        cipher.resize(total);

        vector<unsigned char> tag(TAG);

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                TAG, tag.data()) != 1) {
            cout << "Authentication tag generation failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        // Store nonce + ciphertext + tag in encrypted file.
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), cipher.begin(), cipher.end());
        result.insert(result.end(), tag.begin(), tag.end());

        if (!writeFile(output, result) || !writeFile(keyFile, key)) {
            cout << "Could not save encrypted file or key.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        cout << "Encryption successful.\n";

    } else if (choice == 2) {
        if (data.size() < NONCE + TAG ||
            !readFile(keyFile, key) || key.size() != KEY) {
            cout << "Invalid encrypted file or key.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        copy(data.begin(), data.begin() + NONCE, nonce.begin());

        vector<unsigned char> cipher(data.begin() + NONCE, data.end() - TAG);
        vector<unsigned char> tag(data.end() - TAG, data.end());

        result.resize(cipher.size() + 16);

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                              nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                NONCE, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                              key.data(), nonce.data()) != 1) {
            cout << "Decryption setup failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        if (EVP_DecryptUpdate(ctx, result.data(), &len,
                              cipher.data(), cipher.size()) != 1) {
            cout << "Decryption failed.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        total = len;

        // Set tag; finalization checks whether data was modified.
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                TAG, tag.data()) != 1) {
            cout << "Authentication tag error.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        if (EVP_DecryptFinal_ex(ctx, result.data() + total, &len) != 1) {
            cout << "Authentication failed: wrong key or modified file.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        total += len;
        result.resize(total);

        if (!writeFile(output, result)) {
            cout << "Could not save recovered file.\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }

        cout << "Decryption successful.\n";

    } else {
        cout << "Choose 1 or 2.\n";
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
}
