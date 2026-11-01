#include <cstdint>
#include <iostream>

using u64 = std::uint64_t;

bool isPrime(u64 n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    for (u64 divisor = 3; divisor <= n / divisor; divisor += 2) {
        if (n % divisor == 0) return false;
    }
    return true;
}

u64 modPow(u64 base, u64 exponent, u64 modulus) {
    u64 result = 1;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1ULL) result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1ULL;
    }
    return result;
}


bool isPrimitiveRoot(u64 g, u64 p) {
    u64 remaining = p - 1;
    for (u64 factor = 2; factor <= remaining / factor; ++factor) {
        if (remaining % factor == 0) {
            if (modPow(g, (p - 1) / factor, p) == 1) return false;
            while (remaining % factor == 0) remaining /= factor;
        }
    }
    if (remaining > 1 && modPow(g, (p - 1) / remaining, p) == 1) return false;
    return true;
}

int main() {
    u64 p = 23, g = 5;
    std::cout << "=== Diffie-Hellman Key Exchange and MITM Demonstration ===\n";
    std::cout << "Enter prime modulus p (2..1,000,000,000) [default 23]: ";
    std::string line;
    std::getline(std::cin, line);
    if (!line.empty()) {
        try { p = std::stoull(line); }
        catch (...) { std::cerr << "Invalid p.\n"; return 1; }
    }
    if (p < 5 || p > 1'000'000'000ULL || !isPrime(p)) {
        std::cerr << "p must be a prime between 5 and 1,000,000,000.\n";
        return 1;
    }

    std::cout << "Enter generator/base g (2..p-2) [default 5]: ";
    std::getline(std::cin, line);
    if (!line.empty()) {
        try { g = std::stoull(line); }
        catch (...) { std::cerr << "Invalid g.\n"; return 1; }
    }
    if (g < 2 || g > p - 2 || !isPrimitiveRoot(g, p)) {
        std::cerr << "g must be a primitive root modulo p (between 2 and p-2).\n";
        return 1;
    }

    u64 alicePrivate = 6, bobPrivate = 15, eveForBob = 7, eveForAlice = 9;
    std::cout << "Enter Alice's private value [default 6]: ";
    std::getline(std::cin, line);
    if (!line.empty()) { try { alicePrivate = std::stoull(line); } catch (...) { return 1; } }
    std::cout << "Enter Bob's private value [default 15]: ";
    std::getline(std::cin, line);
    if (!line.empty()) { try { bobPrivate = std::stoull(line); } catch (...) { return 1; } }
    std::cout << "Enter Eve's value for Alice-facing key [default 7]: ";
    std::getline(std::cin, line);
    if (!line.empty()) { try { eveForBob = std::stoull(line); } catch (...) { return 1; } }
    std::cout << "Enter Eve's value for Bob-facing key [default 9]: ";
    std::getline(std::cin, line);
    if (!line.empty()) { try { eveForAlice = std::stoull(line); } catch (...) { return 1; } }

    const u64 values[] = {alicePrivate, bobPrivate, eveForBob, eveForAlice};
    for (u64 value : values) {
        if (value < 1 || value > p - 2) {
            std::cerr << "All private values must be between 1 and p-2.\n";
            return 1;
        }
    }

    const u64 alicePublic = modPow(g, alicePrivate, p);
    const u64 bobPublic = modPow(g, bobPrivate, p);
    const u64 aliceNormalKey = modPow(bobPublic, alicePrivate, p);
    const u64 bobNormalKey = modPow(alicePublic, bobPrivate, p);

    std::cout << "\n--- Normal Diffie-Hellman ---\n";
    std::cout << "Alice public value: " << alicePublic << '\n';
    std::cout << "Bob public value:   " << bobPublic << '\n';
    std::cout << "Alice shared key:   " << aliceNormalKey << '\n';
    std::cout << "Bob shared key:     " << bobNormalKey << '\n';
    std::cout << "Shared keys match:  " << (aliceNormalKey == bobNormalKey ? "YES" : "NO") << '\n';

    // Eve replaces Alice's public value sent to Bob and Bob's value sent to Alice.
    const u64 eveToBob = modPow(g, eveForBob, p);
    const u64 eveToAlice = modPow(g, eveForAlice, p);
    const u64 aliceMitmKey = modPow(eveToAlice, alicePrivate, p);
    const u64 bobMitmKey = modPow(eveToBob, bobPrivate, p);
    const u64 eveAliceKey = modPow(alicePublic, eveForAlice, p);
    const u64 eveBobKey = modPow(bobPublic, eveForBob, p);

    std::cout << "\n--- Man-in-the-Middle Attack ---\n";
    std::cout << "Eve sends to Alice: " << eveToAlice << '\n';
    std::cout << "Eve sends to Bob:   " << eveToBob << '\n';
    std::cout << "Alice's key (with Eve): " << aliceMitmKey << '\n';
    std::cout << "Eve's key with Alice:   " << eveAliceKey << '\n';
    std::cout << "Bob's key (with Eve):   " << bobMitmKey << '\n';
    std::cout << "Eve's key with Bob:     " << eveBobKey << '\n';
    std::cout << "Eve matches both sides: "
              << ((aliceMitmKey == eveAliceKey && bobMitmKey == eveBobKey) ? "YES" : "NO") << '\n';

    std::cout << "\nNote: Small parameters are for demonstration only. Real DH must use strong groups and authentication.\n";
    return 0;
}
