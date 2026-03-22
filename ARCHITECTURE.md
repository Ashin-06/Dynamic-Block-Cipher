# Cryptographic Architecture Specification

This document provides a detailed specification of the architecture of the Dynamic Block Cipher (Secure GFN v2). The cipher is designed to provide high-grade confidentiality, integrity, and resistance to cryptanalysis through modern symmetric design principles.

---

## 1. Design Overview

The Dynamic Block Cipher is a symmetric key block cipher structured as a **4-Branch Type-II Generalized Feistel Network (GFN)**.

### Core Primitives
* **Block Size:** 4096 bits (512 bytes)
* **Word Size:** 1024 bits (128 bytes) per branch ($b = 4$ branches)
* **Round Count:** 32 rounds
* **Key Derivation Function:** PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt)
* **Master Key Size:** 256 bits
* **Round Subkeys:** 64 subkeys, 1024 bits each (derived via HMAC-SHA256 counter-mode key schedule)
* **Authenticated Encryption:** Encrypt-then-MAC (EtM) paradigm using HMAC-SHA256
* **Mode of Operation:** Cipher Block Chaining (CBC) with a cryptographically secure random IV

---

## 2. Feistel Structure: 4-Branch Type-II GFN

A Type-II GFN splits the block into $b$ words and applies a round function to alternate words, XORing the result into adjacent words before cyclic-shifting the branch positions. For $b = 4$ branches of size 1024 bits each:

Given input block $X^{(r)} = (X_0^{(r)}, X_1^{(r)}, X_2^{(r)}, X_3^{(r)})$:

$$\begin{aligned}
F_0 &= \text{RoundFunction}(X_1^{(r)}, K_{2r}) \\
F_1 &= \text{RoundFunction}(X_3^{(r)}, K_{2r+1}) \\
Y_0 &= X_0^{(r)} \oplus F_0 \\
Y_2 &= X_2^{(r)} \oplus F_1
\end{aligned}$$

The next round's input is a cyclic left-shift of the branches:

$$X^{(r+1)} = (X_1^{(r)}, Y_2, X_3^{(r)}, Y_0)$$

This design achieves full diffusion (where every output bit depends on every input bit) within a few rounds, while allowing parallel computation of the two round functions $F_0$ and $F_1$.

---

## 3. The Round Function $F(X, K)$

The round function operates on a 1024-bit word $X$ and a 1024-bit round subkey $K$. It is designed as a Substitution-Permutation Network (SPN) block, consisting of three main layers:

```
    Input Word (1024-bit) & Subkey (1024-bit)
                  │             │
                  └───►  XOR  ◄─┘
                         │
              [ Substitution Layer ]
            (AES S-Box byte-by-byte)
                         │
               [ Diffusion Layer ]
           (1024-bit Bit Permutation)
                         │
             [ Linear Mixing Layer ]
        (Circular Bit Rotation & XOR)
                         │
                       Output
```

### 3.1 Key Addition
The input word is XORed with the round subkey $K$:

$$A = X \oplus K$$

### 3.2 Substitution Layer (Confusion)
The word $A$ (128 bytes) is passed through a byte-by-byte substitution layer using the standard AES (Rijndael) S-box.
* **Non-linearity:** The Rijndael S-box is based on the mapping $x \mapsto x^{-1}$ over the Galois Field $\text{GF}(2^8)$ followed by an affine transformation. This ensures an algebraic degree of 7, eliminating linear approximations with high bias.
* **Differential Uniformity:** The S-box has a maximum differential uniformity of 4, ensuring high resistance to differential cryptanalysis.

### 3.3 Bit Permutation (Diffusion)
A fixed, pseudo-randomly generated but deterministic 1024-bit permutation table is used to shuffle the bit positions. This breaks byte boundaries, scattering the output of the S-boxes across the entire 1024-bit word.

### 3.4 Linear Mixing Layer (SAC Hardening)
To satisfy the **Strict Avalanche Criterion (SAC)** (where flipping a single input bit changes each output bit with a probability of 512/1024 = 50%), a wide-block linear mixing layer is applied.
The permuted 128-byte block is split into sixteen 64-bit (8-byte) sub-words. These sub-words are mixed using circular bit shifts and XOR operations:

$$W_i = \text{PermutedSubWord}_i$$

For each $i \in [0, 15]$:

$$Mixed_i = W_i \oplus (W_{(i+1) \bmod 16} \lll 17) \oplus (W_{(i+5) \bmod 16} \lll 31)$$

This wide-block mixing ensures that the avalanche effect propagates rapidly across all branches.

---

## 4. Key Schedule & Subkey Derivation

To prevent related-key attacks and ensure that round subkeys are cryptographically independent, subkeys are derived using HMAC-SHA256 in counter-mode.

### 4.1 Master Key Derivation
The user's passphrase is input to PBKDF2-HMAC-SHA256:

$$\text{MasterKey} = \text{PBKDF2}(\text{Passphrase}, \text{Salt}, \text{iterations}=600\,000, \text{length}=32\text{ bytes})$$

* **Salt:** A cryptographically secure random 16-byte value generated per-file/session.
* **Master Key Split:** The 32-byte Master Key is split into:
  1. $k_{enc}$ (16 bytes): Encryption key.
  2. $k_{mac}$ (16 bytes): MAC authentication key.

### 4.2 Subkey Generation
For each of the 32 rounds, two 1024-bit subkeys ($K_{2r}$ and $K_{2r+1}$) are required, totalling 64 subkeys.
Since each subkey is 128 bytes (1024 bits) and SHA-256 outputs 32 bytes, we generate each subkey by concatenating four HMAC executions with a counter:

$$K_j = \text{HMAC}(k_{enc}, j \parallel 0) \parallel \text{HMAC}(k_{enc}, j \parallel 1) \parallel \text{HMAC}(k_{enc}, j \parallel 2) \parallel \text{HMAC}(k_{enc}, j \parallel 3)$$

This guarantees that the subkeys behave as outputs of a cryptographically secure pseudo-random function (PRF), making it computationally impossible to derive the master key from any number of compromised subkeys.

---

## 5. Authenticated Mode: Encrypt-then-MAC (EtM)

The cipher implements the **Encrypt-then-MAC** (EtM) paradigm using HMAC-SHA256, which is mathematically proven to be the most secure AEAD composition method.

### 5.1 Format of Ciphertext Payload
The final output is formatted as follows:

```
┌─────────────────┬──────────────────┬──────────────────────┬──────────────────────┐
│  Salt (16 B)    │   IV (512 B)     │ Ciphertext (N×512 B) │  HMAC Tag (32 B)     │
└─────────────────┴──────────────────┴──────────────────────┴──────────────────────┘
```

* **Salt (16 bytes):** Used to derive $k_{enc}$ and $k_{mac}$ via PBKDF2.
* **IV (512 bytes):** Initialization Vector generated via `os.urandom()` for CBC mode.
* **Ciphertext:** Encrypted blocks padded using PKCS#7.
* **HMAC Tag (32 bytes):** Computed over the concatenated payload:
  $$\text{Tag} = \text{HMAC-SHA256}(k_{mac}, \text{Salt} \parallel \text{IV} \parallel \text{Ciphertext})$$

### 5.2 Decryption Verification
During decryption, the receiver computes the expected HMAC tag over the received Salt, IV, and Ciphertext, and compares it with the appended tag using constant-time comparison (`hmac.compare_digest`). If they match, decryption proceeds; otherwise, it is aborted immediately. This protects against:
* **Padding Oracle Attacks:** Because the tag is verified *before* decryption/unpadding, the padding is never parsed if the ciphertext was tampered with.
* **Timing Attacks:** The constant-time comparison prevents attackers from learning information about the tag verification speed.
