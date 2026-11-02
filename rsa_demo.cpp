#include <bits/stdc++.h>
using namespace std;

// Calculates (base^exp) % mod
long long modPow(long long base, long long exp, long long mod) {
    long long ans = 1;
    while (exp > 0) {
        if (exp % 2) ans = (ans * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return ans;
}

// Checks whether a number is prime
bool isPrime(long long n) {
    if (n < 2) return false;
    for (long long i = 2; i * i <= n; i++)
        if (n % i == 0) return false;
    return true;
}

int main() {
    long long p, q, e, msg;

    cout << "Enter two different small primes p and q: ";
    cin >> p >> q;

    if (p > 30000 || q > 30000 || p == q ||
        !isPrime(p) || !isPrime(q)) {
        cout << "Enter different prime numbers (each <= 30000).\n";
        return 1;
    }

    long long n = p * q;
    long long phi = (p - 1) * (q - 1);

    cout << "Enter public exponent e: ";
    cin >> e;

    if (e <= 1 || e >= phi || gcd(e, phi) != 1) {
        cout << "Invalid public exponent.\n";
        return 1;
    }

    // Find private exponent d such that (e*d) % phi = 1
    long long d = 1;
    while (d < phi && (e * d) % phi != 1)
        d++;

    if (d == phi) {
        cout << "Could not find private key.\n";
        return 1;
    }

    cout << "Enter numeric message (less than " << n << "): ";
    cin >> msg;

    if (!cin || msg < 0 || msg >= n) {
        cout << "Invalid message.\n";
        return 1;
    }

    // Encryption: C = M^e mod n
    long long cipher = modPow(msg, e, n);

    // Decryption: M = C^d mod n
    long long plain = modPow(cipher, d, n);

    cout << "\nn = " << n;
    cout << "\nphi = " << phi;
    cout << "\nPublic key = (" << e << "," << n << ")";
    cout << "\nPrivate key = (" << d << "," << n << ")";
    cout << "\nCiphertext = " << cipher;
    cout << "\nDecrypted message = " << plain << "\n";
}
