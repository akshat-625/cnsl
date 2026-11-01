# CNSL Lab – Cryptography Practicals (C++17)

This repository contains six cryptography practicals. The programs are written in C++17 and are intended for lab demonstrations and viva preparation.

## 1. Setup and execution

### Requirements

- Ubuntu or Ubuntu on Windows (WSL)
- `g++` and `make`
- OpenSSL development library

Install everything on Ubuntu/WSL:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev openssl
```

### Compile all programs

Open the terminal in the folder containing `Makefile` and run:

```bash
make
```

### Run a program

```bash
./rsa_demo
./rsa_benchmark
./custom
./dh
./sha1
./signature
```

The image practical takes command-line arguments. Its commands are shown in Practical 6.

To compile only one program, use `make` followed by its target name, for example:

```bash
make rsa_demo
make signature
```

To remove generated executables and sample output files:

```bash
make clean
```

> **Windows note:** These instructions use Ubuntu/Linux terminal commands. On Windows, run them in Ubuntu through WSL. PowerShell is fine for Git commands, but use Ubuntu/WSL for the `make` and `./program` commands.

---

## Practical 1 – RSA: Key generation, encryption/decryption and performance

### Question

Measure the time required for RSA key-pair generation, encryption and decryption for different RSA key sizes and message sizes.

### Technical words used in the code

- `p`, `q` – two different prime numbers.
- `n = p * q` – RSA modulus.
- `phi(n)` – Euler totient, calculated as `(p-1) * (q-1)` in the small-number demonstration.
- `e` – public exponent.
- `d` – private exponent, calculated as the modular inverse of `e` modulo `phi(n)`.
- `gcd()` – checks whether two numbers are coprime.
- `modPow()` – performs modular exponentiation efficiently.
- `EVP_PKEY_keygen()` – generates an RSA key pair using OpenSSL.
- `EVP_PKEY_encrypt()` / `EVP_PKEY_decrypt()` – encrypts and decrypts data using the generated key.
- `RSA_PKCS1_OAEP_PADDING` – RSA-OAEP padding used for safer RSA encryption.
- `EVP_sha256()` – selects SHA-256 for OAEP.
- `steady_clock` – measures elapsed time.
- `ms` / `us` – milliseconds / microseconds.

### Implementation

There are two source files for this practical:

1. `rsa_demo.cpp` – demonstrates the RSA calculation with small numbers. It accepts `p`, `q`, `e` and a numeric message, then displays the public key, private key, ciphertext and decrypted message.
2. `rsa_benchmark.cpp` – uses OpenSSL to generate RSA keys of selected sizes, creates random messages of selected bit lengths, measures encryption/decryption time and checks that decryption returns the original message.

### Example input – `rsa_demo.cpp`

Run:

```bash
./rsa_demo
```

Enter:

```text
p = 17
q = 11
e = 7
message = 88
```

Expected important output:

```text
n = 187
phi(n) = 160
Public key  = (7, 187)
Private key = (23, 187)
Plaintext   = 88
Ciphertext  = 11
Decrypted   = 88
RSA round-trip successful.
```

### Example input – `rsa_benchmark.cpp`

Run:

```bash
./rsa_benchmark
```

For a short test, enter:

```text
RSA key sizes: 2048
Message sizes: 64,128
Key-generation runs: 1
Encrypt/decrypt runs: 10
```

Expected output format (the measured times will vary by computer):

```text
--- RSA 2048 bits ---
Average key generation time: <measured time> ms
Maximum OAEP-SHA256 message size: 190 bytes
Message 64 bits (8 bytes): encrypt avg <time> us, decrypt avg <time> us; verified
Message 128 bits (16 bytes): encrypt avg <time> us, decrypt avg <time> us; verified
```

**Viva point:** Larger RSA keys generally take longer to generate and use. OAEP-SHA256 also limits the maximum message size; the benchmark skips a message that exceeds that limit. The program's default 1024-bit option is only for classroom comparison and is not secure for new applications. The small-number RSA example is also only for learning.

---

## Practical 2 – Custom encryption and decryption

### Question

Design and implement a simple custom encryption/decryption method for exchanging text between users without calling a standard AES, DES or RSA encryption routine.

### Technical words used in the code

- `XOR` (`^`) – bitwise operation that combines each plaintext byte with a key byte.
- `key[i % key.size()]` – repeats the key when the message is longer than the key.
- `xorTransform()` – applies XOR to every byte.
- `hexadecimal` – represents each encrypted byte using two hex characters so it can be displayed and entered again.
- `fromHex()` – converts the entered hexadecimal ciphertext back into bytes.
- `std::getline()` – reads a complete line, including spaces.

### Implementation

1. Select encrypt or decrypt.
2. Enter a non-empty secret key.
3. For encryption, enter the plaintext. The program XORs it with the repeating key and prints the ciphertext in hexadecimal.
4. For decryption, run the program again, enter the same key and the hexadecimal ciphertext. XOR reverses the operation and returns the original text.

### Example input – encryption

Run:

```bash
./custom
```

Enter:

```text
Choose: 1
Secret key: key
Plaintext: HELLO
```

Expected output:

```text
Ciphertext (hex): 232035272a
```

### Example input – decryption

Run `./custom` again and enter:

```text
Choose: 2
Secret key: key
Ciphertext: 232035272a
```

Expected output:

```text
Decrypted text: HELLO
```

**Important:** This repeating-key XOR program is a classroom demonstration, not secure encryption. It does not authenticate the message and must not be used to protect real files or sensitive data.

---

## Practical 3 – Diffie-Hellman key exchange and Man-in-the-Middle attack

### Question

Implement Diffie-Hellman key exchange between Alice and Bob, then demonstrate how an attacker (Eve) can perform a Man-in-the-Middle (MITM) attack when the exchange is not authenticated.

### Technical words used in the code

- `p` – public prime modulus.
- `g` – public generator / primitive root modulo `p`.
- `a`, `b` – Alice's and Bob's private values.
- `A = g^a mod p` / `B = g^b mod p` – Alice's and Bob's public values.
- `modPow()` – calculates powers modulo `p`.
- `shared key` – both participants calculate the same value: `B^a mod p = A^b mod p`.
- `MITM` – an attacker intercepts and replaces public values, creating one shared key with Alice and another with Bob.
- `isPrimitiveRoot()` – checks whether the selected generator is a primitive root for the prime modulus.

### Implementation

1. Enter the prime `p` and generator `g` (or press Enter to use defaults).
2. Enter private values for Alice, Bob and Eve (or press Enter to use defaults).
3. The program calculates the normal public values and shared keys for Alice and Bob.
4. It then simulates Eve replacing the public values. Alice and Eve calculate one matching key; Bob and Eve calculate a different matching key.

### Example input

Run:

```bash
./dh
```

Press Enter at all prompts to use the defaults:

```text
p = 23
g = 5
Alice private value = 6
Bob private value = 15
Eve private values = 7 and 9
```

Expected important output:

```text
Alice public value: 8
Bob public value:   19
Alice shared key:   2
Bob shared key:     2
Shared keys match:  YES

Eve sends to Alice: 11
Eve sends to Bob:   17
Alice's key (with Eve): 9
Eve's key with Alice:   9
Bob's key (with Eve):   15
Eve's key with Bob:     15
Eve matches both sides: YES
```

**Viva point:** Diffie-Hellman agrees on a shared secret; it does not encrypt the message by itself. Unauthenticated Diffie-Hellman is vulnerable to MITM. Authentication, such as certificates and digital signatures in a secure protocol, prevents an attacker from silently replacing public values. The small values in this program are only for demonstration.

---

## Practical 4 – SHA-1 message digest

### Question

Generate the SHA-1 message digest of an entered message and demonstrate how changing the message changes its digest.

### Technical words used in the code

- `hash` / `digest` – fixed-length output calculated from the input message.
- `SHA-1` – hash function that produces a 160-bit (20-byte) digest.
- `EVP_Digest()` – OpenSSL function that calculates the digest.
- `EVP_sha1()` – selects the SHA-1 algorithm.
- `hexadecimal` – format used to display the digest.
- `avalanche effect` – a small change in input should produce a very different digest.

### Implementation

1. Enter a message.
2. `EVP_Digest()` calculates and displays its SHA-1 digest.
3. The program changes the first character (or uses `A` if the message is empty).
4. It calculates and displays the modified message's digest for comparison.

### Example input

Run:

```bash
./sha1
```

Enter:

```text
Hello
```

Expected output:

```text
SHA-1 digest: f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0
Digest length: 20 bytes (160 bits)
Modified message: Aello
Modified digest: 858136756ea315dd2479fcd8159b247cc2aa9148
```

**Viva point:** A hash is not encryption: it is not designed to be decrypted. SHA-1 is collision-broken and should not be used in new security systems; use a modern hash such as SHA-256 or SHA-3 instead.

---

## Practical 5 – Digital signature using Ed25519

### Question

Generate a digital signature for a message and verify the signature. Also test whether a modified message is rejected.

### Technical words used in the code

- `Ed25519` – a public-key digital signature scheme from the EdDSA family.
- `private key` – used to create the signature; it must remain secret.
- `public key` – used to verify the signature; it can be shared.
- `EVP_PKEY_keygen()` – generates the key pair.
- `EVP_DigestSign()` – creates the digital signature.
- `EVP_DigestVerify()` – checks whether the signature matches the message and public key.
- `integrity` – detects whether the signed message was changed.
- `authentication` – helps verify that the message was signed by the holder of the corresponding private key, provided the public key is trusted.

### Implementation

1. Enter the message to sign.
2. The program generates a temporary Ed25519 key pair.
3. It signs the message using the private key.
4. It verifies the original message using the public key.
5. Enter a test message. To test automatic modification, just press Enter. The modified message should be rejected.

### Example input

Run:

```bash
./signature
```

Enter:

```text
Message to sign: Hello Bob
Test message: [press Enter]
```

Expected result:

```text
Original message: SIGNATURE VERIFIED
Test message: SIGNATURE REJECTED
```

The displayed public key and signature are hexadecimal values and will be different each time because a new key pair is generated on every run.

**Viva point:** A digital signature provides integrity and supports authentication; it does not hide the message. This program demonstrates Ed25519 (EdDSA), not the older DSA algorithm. A real system must also verify that the public key belongs to the claimed person or organisation.

---

## Practical 6 – Secure image/file transmission using AES-256-GCM

### Question

Encrypt an image before transmission and decrypt it at the receiver's end. Detect whether the encrypted data has been modified.

### Technical words used in the code

- `AES-256` – symmetric encryption using a 256-bit key.
- `GCM` – Galois/Counter Mode; provides encryption and authentication.
- `key` – secret 32-byte value used for encryption and decryption.
- `nonce` / `IV` – unique value used for an encryption operation; this program uses 12 bytes.
- `authentication tag` – 16-byte value used to detect tampering or an incorrect key.
- `RAND_bytes()` – generates cryptographically secure random bytes for the key and nonce.
- `EVP_aes_256_gcm()` – selects AES-256-GCM in OpenSSL.
- `EVP_EncryptUpdate()` – encrypts the file data.
- `EVP_DecryptUpdate()` – processes encrypted data during decryption.
- `EVP_DecryptFinal_ex()` – verifies GCM authentication; decryption fails if the key or encrypted data is incorrect or modified.

### Implementation

1. Keep an image such as `photo.jpg` in the same directory as the program. (The program can encrypt other file types too.)
2. Run the encryption command. The program generates a random key and nonce, encrypts the file and saves the key separately.
3. Transfer the encrypted file through the channel.
4. Run the decryption command with the correct key. The program verifies the authentication tag before writing the recovered file.

### Example input – encryption

```bash
./image encrypt photo.jpg encrypted.bin key.bin
```

Expected output:

```text
Encryption successful. Encrypted data: encrypted.bin
Key file: key.bin
```

### Example input – decryption

```bash
./image decrypt encrypted.bin recovered.jpg key.bin
```

Expected output:

```text
Decryption and authentication successful. Recovered file: recovered.jpg
```

**Viva point:** If the encrypted file is modified or the wrong key is supplied, authentication fails and the program does not write the recovered file. Keep `key.bin` secret. Do not upload it to GitHub or send it with the encrypted file over an unsecured channel. Never reuse a GCM nonce with the same key. This classroom program reads the complete file into memory and supports files up to about 2 GB.

---

## Quick viva revision

- **RSA:** asymmetric encryption; public key encrypts, private key decrypts; `n = p*q`.
- **XOR:** `A ^ B ^ B = A`; the same repeating key reverses the operation.
- **Diffie-Hellman:** both sides derive the same shared secret; authentication is needed to stop MITM.
- **SHA-1:** one-way hash; 160-bit output; not encryption.
- **Digital signature:** private key signs; public key verifies; does not provide confidentiality.
- **AES-GCM:** symmetric authenticated encryption; key secrecy and nonce uniqueness are important.

## Source files

| File | Purpose |
|---|---|
| `rsa_demo.cpp` | Small numerical RSA example |
| `rsa_benchmark.cpp` | RSA key-generation/encryption/decryption timing benchmark |
| `custom.cpp` | Repeating-key XOR text demonstration |
| `dh.cpp` | Diffie-Hellman and MITM demonstration |
| `sha1.cpp` | SHA-1 message digest |
| `signature.cpp` | Ed25519 signing and verification |
| `image.cpp` | AES-256-GCM image/file encryption and decryption |
| `Makefile` | Builds all programs |
| `.gitignore` | Excludes executables and generated key/encrypted files |

---

**Language:** C++17  
**Crypto library:** OpenSSL  
**Recommended lab environment:** Ubuntu / Ubuntu on WSL
