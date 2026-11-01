# Cryptography Practicals in C++ (Ubuntu)

A collection of six cryptography practicals implemented in C++17. The programs are designed for classroom demonstrations and run from the Ubuntu terminal (including Ubuntu on WSL).

> **Important:** Some programs use deliberately small or educational techniques to demonstrate concepts. They are not all suitable for protecting real data. Read the security notes for each practical before using them outside a lab.

## Contents

| Practical | Source file(s) | What it demonstrates | OpenSSL required? |
|---|---|---|---|
| 1. RSA | `rsa_demo.cpp`, `rsa_benchmark.cpp` | Numeric RSA example and timing of key generation, encryption and decryption | Benchmark: Yes; numeric demo: No |
| 2. Custom encryption | `custom.cpp` | Repeating-key XOR encryption and decryption of text | No |
| 3. Diffie-Hellman | `dh.cpp` | Shared-key agreement and a man-in-the-middle (MITM) demonstration | No |
| 4. SHA-1 | `sha1.cpp` | Message digest generation and the effect of changing a message | Yes |
| 5. Digital signature | `signature.cpp` | Ed25519 key generation, signing and signature verification | Yes |
| 6. Secure image/file transmission | `image.cpp` | AES-256-GCM file encryption, authenticated decryption and tamper detection | Yes |

## 1. Requirements and installation

The instructions below are for Ubuntu or Ubuntu on Windows Subsystem for Linux (WSL).

Install the C++ compiler, Make and OpenSSL development libraries:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev openssl
```

Verify the tools:

```bash
g++ --version
make --version
openssl version
```

## 2. Get the project

After uploading this folder to GitHub, clone your repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

Or, when working with a downloaded ZIP, extract it and use `cd` to enter the extracted `Crypto_Practicals` folder.

## 3. Compile all programs

Run this command inside the project folder:

```bash
make
```

The `Makefile` builds all seven executables. There are seven source files because Practical 1 includes both a small numerical RSA example and a separate RSA performance benchmark.

To compile only one program, use the corresponding command:

```bash
g++ -std=c++17 rsa_demo.cpp -o rsa_demo
g++ -std=c++17 rsa_benchmark.cpp -o rsa_benchmark -lcrypto
g++ -std=c++17 custom.cpp -o custom
g++ -std=c++17 dh.cpp -o dh
g++ -std=c++17 sha1.cpp -o sha1 -lcrypto
g++ -std=c++17 signature.cpp -o signature -lcrypto
g++ -std=c++17 image.cpp -o image -lcrypto
```

`-lcrypto` links the OpenSSL cryptography library. It is needed by the benchmark, SHA-1, signature and AES-GCM programs.

## 4. Run each practical

### Practical 1A — RSA numerical demonstration

Run:

```bash
./rsa_demo
```

Enter the two distinct prime numbers, public exponent and numeric plaintext. For the example used in the assignment, enter:

```text
p = 17
q = 11
e = 7
message = 88
```

Expected key values and result:

```text
n = 187
phi(n) = 160
Public key = (7, 187)
Private key = (23, 187)
Ciphertext = 11
Decrypted = 88
RSA round-trip successful.
```

The program validates the primes, exponent and message range. The small values are for hand calculation and learning only.

### Practical 1B — RSA performance benchmark

Run:

```bash
./rsa_benchmark
```

The program asks for:

- RSA key sizes in bits, comma-separated (default: `1024,2048,3072`).
- Message sizes in bits, comma-separated (default: `64,128,256,512,1024`).
- Number of key-generation runs (default: `1`).
- Number of encryption/decryption runs per message size (default: `100`).

Press Enter to accept a default. It reports average key-generation time and average encryption/decryption time. Each decrypted result is checked against the original message.

This benchmark uses RSA-OAEP with SHA-256. RSA has a strict maximum plaintext size: for OAEP-SHA256 it is `modulus size in bytes - 66`. Message sizes that exceed this limit are skipped and reported. A 1024-bit key is included only to compare classroom timings; do not use it for real security. Timings depend on the computer, OpenSSL version and system load.

### Practical 2 — Custom XOR encryption/decryption

Run:

```bash
./custom
```

Choose `1` to encrypt or `2` to decrypt. Enter the same secret key for both operations. Encryption accepts text and prints the ciphertext as hexadecimal. To decrypt, run the program again, choose `2`, and enter the hexadecimal ciphertext and the same key.

**Security limitation:** This is a repeating-key XOR demonstration, not a secure custom cipher. It has no authentication and is vulnerable to known-plaintext and other attacks. Do not use it for actual startup files or sensitive data. Real applications should use a vetted authenticated-encryption scheme and sound key management.

### Practical 3 — Diffie-Hellman and MITM attack

Run:

```bash
./dh
```

Enter the prime modulus, generator, Alice's private value, Bob's private value and Eve's two private values. Press Enter at each prompt to use the sample defaults:

```text
p = 23
g = 5
Alice private value = 6
Bob private value = 15
Eve value for Alice-facing key = 7
Eve value for Bob-facing key = 9
```

The first section shows Alice and Bob deriving the same shared key. The second section shows Eve replacing the public values and deriving a separate key with each participant. The program checks that Eve's values match Alice's and Bob's MITM-side keys.

The small parameters are intentionally insecure. Real Diffie-Hellman requires strong parameters and authentication (for example, authenticated key exchange in TLS) to prevent MITM attacks.

### Practical 4 — SHA-1 message digest

Run:

```bash
./sha1
```

Enter any message. The program prints its SHA-1 digest, its length, then changes one character and calculates a second digest to demonstrate that a small input change produces a different digest.

SHA-1 produces a 160-bit (20-byte) digest. It is collision-broken and must not be selected for new security designs. Use SHA-256 or SHA-3 for new applications.

### Practical 5 — Digital signature (Ed25519)

Run:

```bash
./signature
```

Enter a message to sign. The program creates an Ed25519 key pair, signs the message with the private key, prints the public key and signature in hexadecimal, and verifies the original message. Then enter a test message; press Enter to automatically test a modified version of the original. The modified message should be rejected.

This program generates a temporary key pair each time it runs. It demonstrates signing and verification, but it does not establish a real person's or vendor's identity. A real system must securely store private keys and authenticate the owner of each public key.

### Practical 6 — AES-256-GCM image/file encryption

Place an image (for example, `photo.jpg`) in the project folder. The program works with arbitrary files, not only images.

Encrypt:

```bash
./image encrypt photo.jpg encrypted.bin key.bin
```

Decrypt:

```bash
./image decrypt encrypted.bin recovered.jpg key.bin
```

The encrypted file contains a format marker, a random 12-byte nonce, the ciphertext and a 16-byte authentication tag. The program generates a 32-byte AES key and writes it to `key.bin`. On decryption, the authentication tag is checked before the recovered file is written. A wrong key or modified encrypted file should cause authentication to fail.

**Protect `key.bin`.** Anyone who obtains it can decrypt the file. Do not upload it to GitHub or send it beside the ciphertext over an unsecured channel. Share the key using a secure authenticated key-exchange mechanism. AES-GCM nonces must never be reused with the same key. This classroom program reads the whole file into memory and is limited to files of about 2 GB; it is not a streaming file-encryption tool.

## 5. Clean generated executables

To remove compiled programs and common generated outputs:

```bash
make clean
```

## 6. Suggested GitHub upload steps

From the parent directory of `Crypto_Practicals`:

```bash
git init
git add README.md Makefile .gitignore *.cpp
git commit -m "Add C++ cryptography practicals"
git branch -M main
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
```

Check the files being staged before committing. Never add private keys, API keys, passwords, `key.bin`, or other generated secret material. The included `.gitignore` excludes the generated `*.bin` files and executables.

## 7. References

- [OpenSSL documentation](https://docs.openssl.org/)
- [OpenSSL RSA key support](https://docs.openssl.org/3.1/man7/EVP_PKEY-RSA/)
- [OpenSSL Ed25519 support](https://docs.openssl.org/3.4/man7/EVP_SIGNATURE-ED25519/)
- [OpenSSL authenticated encryption overview](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)
- [Ubuntu package management](https://ubuntu.com/server/docs/how-to/software/package-management/)

---

**Language:** C++17  
**Tested build environment:** Ubuntu-compatible GCC and OpenSSL using the system `g++` compiler and `-lcrypto`.
