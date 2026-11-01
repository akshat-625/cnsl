#include <cstdint>
#include <iostream>
#include <limits>
#include <numeric>

using u64 = std::uint64_t;
using i128 = __int128_t;
using u128 = __uint128_t;

bool isPrime(u64 n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    for (u64 d = 3; d <= n / d; d += 2) {
        if (n % d == 0) return false;
    }
    return true;
}

u64 modPow(u64 base, u64 exponent, u64 modulus) {
    u64 result = 1 % modulus;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1ULL)
            result = static_cast<u64>((static_cast<u128>(result) * base) % modulus);
        base = static_cast<u64>((static_cast<u128>(base) * base) % modulus);
        exponent >>= 1ULL;
    }
    return result;
}

i128 extendedGcd(i128 a, i128 b, i128 &x, i128 &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    i128 x1 = 0, y1 = 0;
    i128 gcd = extendedGcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

bool modularInverse(u64 e, u64 phi, u64 &d) {
    i128 x = 0, y = 0;
    i128 gcd = extendedGcd(static_cast<i128>(e), static_cast<i128>(phi), x, y);
    if (gcd != 1) return false;
    i128 value = x % static_cast<i128>(phi);
    if (value < 0) value += static_cast<i128>(phi);
    d = static_cast<u64>(value);
    return true;
}

int main() {
    u64 p = 0, q = 0, e = 0, message = 0;

    std::cout << "=== RSA Numerical Demonstration ===\n";
    std::cout << "Enter prime p (2 to 1,000,000,000): ";
    if (!(std::cin >> p)) {
        std::cerr << "Invalid input for p.\n";
        return 1;
    }
    std::cout << "Enter a different prime q (2 to 1,000,000,000): ";
    if (!(std::cin >> q)) {
        std::cerr << "Invalid input for q.\n";
        return 1;
    }

    if (p > 1'000'000'000ULL || q > 1'000'000'000ULL || !isPrime(p) || !isPrime(q) || p == q) {
        std::cerr << "p and q must be distinct primes not greater than 1,000,000,000.\n";
        return 1;
    }

    const u64 n = p * q;
    const u64 phi = (p - 1) * (q - 1);

    std::cout << "Enter public exponent e (coprime with phi=" << phi << "): ";
    if (!(std::cin >> e) || e <= 1 || e >= phi || std::gcd(e, phi) != 1) {
        std::cerr << "Invalid e. It must satisfy 1 < e < phi and gcd(e, phi) = 1.\n";
        return 1;
    }

    u64 d = 0;
    if (!modularInverse(e, phi, d)) {
        std::cerr << "Could not calculate the private exponent.\n";
        return 1;
    }

    std::cout << "Enter a numeric plaintext message m (0 to " << (n - 1) << "): ";
    if (!(std::cin >> message) || message >= n) {
        std::cerr << "Invalid message. It must be smaller than n.\n";
        return 1;
    }

    const u64 ciphertext = modPow(message, e, n);
    const u64 recovered = modPow(ciphertext, d, n);

    std::cout << "\n--- RSA Values ---\n";
    std::cout << "n = p * q = " << n << '\n';
    std::cout << "phi(n) = (p - 1) * (q - 1) = " << phi << '\n';
    std::cout << "Public key  = (e, n) = (" << e << ", " << n << ")\n";
    std::cout << "Private key = (d, n) = (" << d << ", " << n << ")\n";
    std::cout << "Plaintext   = " << message << '\n';
    std::cout << "Ciphertext  = " << ciphertext << '\n';
    std::cout << "Decrypted   = " << recovered << '\n';
    std::cout << (recovered == message ? "RSA round-trip successful.\n" : "RSA round-trip FAILED.\n");
    std::cout << "\nNote: This small-number RSA program is for learning only, not real security.\n";
    return recovered == message ? 0 : 1;
}
