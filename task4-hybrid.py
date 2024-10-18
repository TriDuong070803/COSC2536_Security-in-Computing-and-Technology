# Hybrid code of RSA and AES encryption and decryption of task 1 
# Requirements: The program must decrypt and encrypt the given text file using hybrid encryption.
# That is, Symmetrical and Asymmetrical encryption.
# The task must also display the key, encrypted and decrypted output to the user.
# The key and outputs must be stored in their relevant folders, titled 'keys' and 'output' respectively.
# The task also makes use of 'task-1.txt' input held in the 'input folder'
# All paths must use the BASE variable to ensure the code works on all operation systems (OS)

#This code was developed from the base code (hybrid_crypto.py) from Lectorial (week 7, Lecture 7)
# The code is also debugged with ChatGPT.
# The parts of the code that are inspired from lecture material are:

# Generation of RSA keys (which has been slightly with the aid of ChatGPT)
# Encryption of data with AES and RSA with padding.
# Decryption of data (which has been altered with the aid of ChatGPT)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os
from os import urandom

# Base variable for file paths (this allows it to be used on all operating systems)
BASE = os.path.dirname(os.path.abspath(__file__))

# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()

    # Save private key to a file

    with open(os.path.join(BASE, 'keys', 'private_key_hybrid_2048.pem'), 'wb') as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # Save public key to a file

    with open(os.path.join(BASE, 'keys', 'public_key_hybrid_2048.pem'), 'wb') as f:
        f.write(public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return private_key, public_key


# Function to encrypt the file using hybrid encryption

def encrypt_file(input_file_path, public_key):
    # Generate a random symmetric key for AES
    symmetric_key = urandom(32) # AES-256

    # Encrypt file with AES
    iv = urandom(16) # Initialisation vector (IV)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file_path, 'rb') as f:
        plaintext = f.read()

    
    # Apply PKCS7 padding to the plaintext
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encrypted_message = encryptor.update(padded_plaintext) + encryptor.finalize()


    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf = asym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    # Save the encrypted content to a file

    with open(os.path.join(BASE, 'output', 'task4_enc.bin'), 'wb') as f:
        f.write(iv + encrypted_message)

    # Save the encypted symmetric key to a file

    with open(os.path.join(BASE, 'keys', 'task4_enc_2048.bin'), 'wb') as f:
        f.write(encrypted_key)

    return encrypted_message, iv, encrypted_key
 
# Function to decrypt the file using hybrid decryption

def decrypt_file(encrypted_file_path, encrypted_key_path, private_key):
    # Read the encrypted symmetric key
    with open(encrypted_key_path, 'rb') as f:
        encrypted_key = f.read()

    # Read the encrypted file content
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_message = f.read()
    
    # Decrypt the symmetric key using RSA
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf = asym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    # Decrypt the file with AES
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # save decrypted content to a file
    with open(os.path.join(BASE, 'output', 'task4_dec.txt'), 'wb') as f:
        f.write(plaintext)

    return plaintext

# Paths for input and output files
input_file = os.path.join(BASE, 'input', 'task1.txt')
encrypted_file = os.path.join(BASE, 'output', 'task4_enc.bin')
encrypted_key_file = os.path.join(BASE, 'keys', 'task4_enc_2048.bin')
decrypted_file = os.path.join(BASE, 'output', 'task4_dec.txt')

# Generate RSA keys
private_key, public_key = generate_rsa_keys()

# Encrypt the file using the public RSA key

encrypted_message, iv, encrypted_key = encrypt_file(input_file, public_key)

# Decrypt the file using the private RSA key
decrypted_message = decrypt_file(encrypted_file, encrypted_key_file, private_key)

# Output the results
print(f"\n{'-' * 10}")
print(f"Generated RSA Private Key: Saved to 'output/private_key_hybrid_2048.pem'")
print(f"Generated RSA Public Key: Saved to 'output/public_key_hybrid_2048.pem'")
print(f"{'-' * 10}")

print(f"Encrypted file has been generated and saved to: {encrypted_file}")
print(f"Encrypted Symmetric Key has been saved to: {encrypted_key_file}")
print(f"{'-' * 10}")

print(f"IV (Initialization Vector): {iv.hex()}")
print(f"Encrypted Data: {encrypted_message.hex()}")
print(f"Encrypted Symmetric Key: {encrypted_key.hex()}")
print(f"{'-' * 10}")

print(f"Decrypted file has been generated and saved to: {decrypted_file}")
print(f"Decrypted Data:\n{decrypted_message.decode('utf-8')}")
print(f"{'-' * 10}")