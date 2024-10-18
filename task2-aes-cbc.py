# This code was developed from the base code (aes_cbc_file.py) from Lectorial (week 5, Lecture 5).

# The parts of the code that are inspired from lecture material are:

# Function to decrypt the cipher with CBC key
# Extract the iv from the ciphertext 
# Remove PKCS7 padding
# Decode the plaintext

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import binascii
import os

# Base variable for file paths
BASE = os.path.dirname(os.path.abspath(__file__))

# function to decrypt the file with CBC key from another file
def decrypt_cbc():

    key = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14")
    ciphertext = binascii.unhexlify("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")

    # Extract the IV (first 16 bytes)
    iv = ciphertext[:16]
    main_ciphertext = ciphertext[16:]
    # Initialize cipher and decryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(main_ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# Prints a line separator
print('─' * 10)

# Decrypt the file using CBC key and ciphertext read from a file
plaintext = decrypt_cbc()
print("Decrypted plaintext: ", plaintext.decode('utf-8'))

# Prints a line separator
print('─' * 10)

# Define the path to store the decrypted plaintext
output_file_path = os.path.join(BASE, "output", "task2_dec.txt")

# Write the plaintext to a file
with open(output_file_path, "w") as file:
    file.write(plaintext.decode('utf-8'))

print(f"Decrypted plaintext stored at {output_file_path}")

# Prints a line separator
print('─' * 10)