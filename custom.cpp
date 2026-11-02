#include <bits/stdc++.h>
using namespace std;

// XOR with the same key performs encryption and decryption.
string xorText(string text, string key) {
    for (int i = 0; i < (int)text.size(); i++)
        text[i] = text[i] ^ key[i % key.size()];

    return text;
}

int main() {
    string message, key;

    cout << "Enter message: ";
    getline(cin, message);

    cout << "Enter secret key: ";
    getline(cin, key);

    if (key.empty()) {
        cout << "Key cannot be empty.\n";
        return 1;
    }

    string cipher = xorText(message, key);

    cout << "Encrypted text (hex): ";

    for (unsigned char c : cipher)
        cout << hex << setw(2) << setfill('0') << (int)c;

    // XOR again with the same key to get original message.
    string decrypted = xorText(cipher, key);

    cout << dec << "\nDecrypted message: " << decrypted << "\n";

    cout << "Note: XOR is only a classroom demonstration, not secure encryption.\n";
}
