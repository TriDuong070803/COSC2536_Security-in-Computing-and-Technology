# symmetric encryption using AES CBC
# mode to generate the secret key and perform encryption and decryption of this text file.
# Requirements: The program must display the key, encrypted and decrypted output to the user. The
# decrypted output must be stored in a separate file. All the file paths must use the BASE variable to
# make the code work on all operating systems 

#This code was developed from the base code (aes_cbc_file.py) from Lectorial (week 5, Lecture 5)
# The parts of the code that are inspired from lecture material are:

# function to derive a key (PBKDF) & salting for added security
# Function to generate a key using the key derivation function (PBKDF) which is used to ensure a strong key is derived from the password
# Using salting for better, ehanced security
# generating a random IV with CBC mode
# Opening the plaintext file in read mode
# adding PKCS7 padding
# Encrypting the data
# creating the encrypted file, writing in it and aditionally adding salt & IV
# Function to decrypt the file.
# calling the encryption and decryption functions


# Make sure all relevant cryptography libararies are installed:
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os

# Base variable for file paths (this allows it to be used on all operating systems)
BASE = os.path.dirname(os.path.abspath(__file__))


def encrypt_file(input_file_path, output_file_path, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # A random Initialisation Vector (IV) is generated for each session
    # This ensures that encryption of the same data results in different ciphertexts
    # Mode = CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Open the task-1.txt plaintext file to be read bytewise
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    #AES operates on blocks of data, so PKCS7 padding is
    # applied to ensure the plaintext is a multiple of the block size.

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypting woohoo !!
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # create the encrypted file, mode = wb (write binary mode)
    # The salt. IV and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return key, ciphertext
    
# Function to decrypt the encrypted file

def decrypt_file(input_file_path, output_file_path, password):
    # open the encrypted file to be read
    with open(input_file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
    )

    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the padded data

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Write the decrypted data to the output file

    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

    # return plaintext to print later
    return plaintext
    

# paths to input and output files
# In order to ensure the files will save on any OS forward slashes (/) have been used
# the os.path command does the rest to ensure that will work on any operating system
# This insight was debugged using ChatGPT on the 17/09/2024
input_file = os.path.join(BASE, 'input/task1.txt')
encrypted_file = os.path.join(BASE, 'output/task1_enc.bin')
decrypted_file = os.path.join(BASE, 'output/task1_dec.txt')


# call encrypted function and collect output

key, ciphertext = encrypt_file(input_file, encrypted_file, 's3945892')

# call the decryption function and collect output

decrypted_text = decrypt_file(encrypted_file, decrypted_file, 's3945892')


# print generated key

print(f"\n{'-' * 10}")
print(f"Generated Key: {key.hex()}")
print(f"{'-' * 10}")

# print message for encrypted file generation
print("Encrypted file has been generated in the output directory")
print(f"{'-' * 10}")

# print encrypted data
print(f"Encrypted Data: {ciphertext.hex()}")
print(f"{'-' * 10}")

# print message for decrypted file generation
print("Decrypted file has been generated in the output directory")
print(f"{'-' * 10}")

# print decrypted data
print(f"Decrypted Data:\n{decrypted_text.decode('utf-8')}")
print(f"{'-' * 10}")