Title: Custom 4-Branch Feistel Cipher (Python)

Description: A symmetric block cipher implementation designed for high-entropy text encryption. This project features a custom Generalized Feistel Network (GFN) architecture that supports dynamic key lengths and large block sizes (up to 4096 bits) to resist standard cryptanalytic attacks.

Key Features:

Architecture: Implements a 4-branch Generalized Feistel Network (GFN) with 32 rounds of permutation.

High Entropy: Utilizes a massive 1024-character key space with 32 unique subkeys derived for each session.

Custom Encoding: Features a proprietary 8-bit to 64-bit binary mapping dictionary to pre-process plaintext and obscure frequency patterns.

Block Size: Optimized for 4096-bit block processing, making it suitable for medium-sized text payloads.
