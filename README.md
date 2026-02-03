# Dynamic Block Cipher (Custom Feistel Network)

![Language](https://img.shields.io/badge/Language-Python_3-blue) ![Status](https://img.shields.io/badge/Status-Educational-orange) ![License](https://img.shields.io/badge/License-Free_Use-green)

## 📌 Overview
This project implements a custom symmetric block cipher designed to secure text data through a **4-branch Generalized Feistel Network (GFN)**. Unlike standard implementations, this algorithm utilizes a dynamic block size (up to 4096 bits) and a massive 1024-character key space to maximize entropy and resist frequency analysis.

The system features a custom binary encoding scheme and a 32-round encryption process, making it a robust educational tool for understanding the principles of **confusion** and **diffusion** in modern cryptography.

## 🚀 Key Features

* **Generalized Feistel Architecture:** Implements a 4-branch variant of the Feistel network, allowing for larger block parallelization compared to the traditional 2-branch design.
* **32-Round Encryption:** Uses 32 distinct rounds of processing to ensure a high avalanche effect, where small changes in input result in drastic changes in ciphertext.
* **Dynamic Key Schedule:** Generates 32 unique subkeys from a master key to prevent key reuse attacks across rounds.
* **Custom Encoding:** Features a proprietary 8-bit to 64-bit binary expansion mapping that obscures plaintext statistics before encryption begins.

## 🛠️ Technical Architecture

The cipher operates on the following principles:
1.  **Preprocessing:** Plaintext is converted into a 64-bit binary representation using a custom dictionary.
2.  **Blocking:** The binary stream is padded and split into 4096-bit blocks.
3.  **Feistel Rounds:**
    * The block is split into 4 sub-blocks.
    * For 32 rounds, sub-blocks are XORed with a round-specific subkey.
    * Sub-blocks are permuted (swapped) to mix data bits.
4.  **Decryption:** The process is reversible by running the same network with the subkeys applied in reverse order.

## 💻 How to Run

### Option 1: Using Jupyter Notebook (Recommended)
This project is built as a Jupyter Notebook (`.ipynb`) for easy visualization of the encryption steps.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Ashin-06/Dynamic-Block-Cipher.git](https://github.com/Ashin-06/Dynamic-Block-Cipher.git)
    ```
2.  **Navigate to the folder:**
    ```bash
    cd Dynamic-Block-Cipher
    ```
3.  **Launch Jupyter:**
    ```bash
    jupyter notebook
    ```
4.  **Open the file:** Click on `Block_Cipher_Implementation.ipynb` in your browser.
5.  **Execute:** Click **"Cell"** > **"Run All"** to see the code generate keys, encrypt the text, and decrypt it back.

### Option 2: Using Python Script
If you prefer running it as a standard script, you can export the notebook as a `.py` file or copy the code into a file named `cipher.py`.

1.  Run the script in your terminal:
    ```bash
    python cipher.py
    ```

### Customizing Input
To test your own text, look for the following line in the code and change the text inside the quotes:
```python
plaintext = 'Your custom text goes here...'
