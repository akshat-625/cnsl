#include <bits/stdc++.h>
using namespace std;

// Calculates (base^exp) mod p
long long powerMod(long long base, long long exp, long long p) {
    long long ans = 1;

    while (exp > 0) {
        if (exp % 2) ans = ans * base % p;
        base = base * base % p;
        exp /= 2;
    }

    return ans;
}

int main() {
    long long p = 23, g = 5;
    long long a, b, x, y;

    cout << "Diffie-Hellman: p=23, g=5\n";

    cout << "Enter Alice private key: ";
    cin >> a;

    cout << "Enter Bob private key: ";
    cin >> b;

    cout << "Enter Eve's private key for Alice side: ";
    cin >> x;

    cout << "Enter Eve's private key for Bob side: ";
    cin >> y;

    if (!cin || a < 1 || a > p-2 || b < 1 || b > p-2 ||
        x < 1 || x > p-2 || y < 1 || y > p-2) {
        cout << "All private values must be from 1 to 21.\n";
        return 1;
    }

    // Normal Diffie-Hellman exchange
    long long A = powerMod(g, a, p);
    long long B = powerMod(g, b, p);

    cout << "\n--- Normal Diffie-Hellman ---\n";
    cout << "Alice shared key: " << powerMod(B, a, p) << "\n";
    cout << "Bob shared key: " << powerMod(A, b, p) << "\n";

    // Eve replaces the public values exchanged by Alice and Bob.
    long long E1 = powerMod(g, x, p);
    long long E2 = powerMod(g, y, p);

    long long aliceKey = powerMod(E2, a, p);
    long long bobKey = powerMod(E1, b, p);

    long long eveAlice = powerMod(A, y, p);
    long long eveBob = powerMod(B, x, p);

    cout << "\n--- Man-in-the-Middle Attack ---\n";

    cout << "Alice's key with Eve: " << aliceKey << "\n";
    cout << "Eve's key with Alice: " << eveAlice << "\n";

    cout << "Bob's key with Eve: " << bobKey << "\n";
    cout << "Eve's key with Bob: " << eveBob << "\n";

    cout << "Eve can establish both keys: "
         << ((aliceKey == eveAlice && bobKey == eveBob) ? "Yes" : "No")
         << "\n";

    cout << "Note: Small p and g are for demonstration only.\n";
}
