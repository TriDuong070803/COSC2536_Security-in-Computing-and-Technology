# This code was developed from the base code (rsa_padding_file.py and rsa_with_signature.py) from Lectorial (week 7).

# The parts of the code that are inspired from lecture material are:

# Using base path for file paths
# Generate RSA keys using cryptography library
# Using OAEP padding for encryption and decryption
# Encrypt the plaintext file
# Decrypt the ciphertext file
# Sign the data
# Verify the signature

# ChatGPT (August 8 Version), OpenAI. Accessed: October 1, 2024. [Online]. Available: https://chatgpt.com/share/6708dc54-4344-8008-b2d3-8fa01622e16f

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import time

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Create keys
def generate_keys(private_key_path, public_key_path, key_size):
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()

    # Convert the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Save the private key to a file
    with open(private_key_path, "wb") as file:
        file.write(private_pem)

    # Save the public key to a file
    with open(public_key_path, "wb") as file:
        file.write(public_pem)

# encrypt plaintext file
def encrypt_file(file_path, public_key_path, output_path):
    # Read the plaintext data from the file
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Read the public key directly from the file
    with open(public_key_path, "rb") as file:
        public_pem = file.read()
        public_key = serialization.load_pem_public_key(public_pem)

    # Encrypt the data using OAEP padding 
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to the specified output file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# decrypt ciphertext file
def decrypt_file(encrypted_file_path, private_key_path, output_path):
    # Read the encrypted data
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()
    
     # Read the private key directly from the file
    with open(private_key_path, "rb") as file:
        private_pem = file.read()
        private_key = serialization.load_pem_private_key(private_pem, password=None)

    # Decrypt the data using OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the decrypted data back to the specified output file
    with open(output_path, "wb") as file:
        file.write(plaintext)

# Sign the data
def sign_data(data, private_key_path):

    # Read the private key directly from the file
    with open(private_key_path, "rb") as file:
        private_pem = file.read()
        private_key = serialization.load_pem_private_key(private_pem, password=None)

    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature
def verify_signature(data, signature, public_key_path):

    # Read the public key directly from the file
    with open(public_key_path, "rb") as file:
        public_pem = file.read()
        public_key = serialization.load_pem_public_key(public_pem)

    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def measure_time(func, *args):
    start_time = time.time()
    func(*args)
    end_time = time.time()
    return end_time - start_time

def main():
    
    # Generate RSA keys for 1024-bit and 2048-bit
    key_sizes = [1024, 2048]
    for key_size in key_sizes:
        print(f"Testing with {key_size}-bit key")
        
        public_key_path = os.path.join(BASE, "keys", f"public_key_{key_size}.pem")
        private_key_path = os.path.join(BASE, "keys", f"private_key_{key_size}.pem")
        generate_keys(private_key_path, public_key_path, key_size)
        
        # Define file paths using BASE for relative paths
        file_path = os.path.join(BASE, "input", "task3.txt")
        encrypted_file_path = os.path.join(BASE, "output", f"task3_enc_{key_size}.bin")
        decrypted_file_path = os.path.join(BASE, "output", f"task3_dec_{key_size}.txt")

        # Measure encryption time
        encryption_time = measure_time(encrypt_file, file_path, public_key_path, encrypted_file_path)
        print(f"Encryption time for {key_size}-bit key: {encryption_time:.4f} seconds")

        # Measure decryption time
        decryption_time = measure_time(decrypt_file, encrypted_file_path, private_key_path, decrypted_file_path)
        print(f"Decryption time for {key_size}-bit key: {decryption_time:.4f} seconds")

        print('─' * 10) 
        
        original_file = file_path

        # Sign the original data
        with open(original_file, "rb") as file:
            original_data = file.read()
        signature = sign_data(original_data, private_key_path)

        # Print the signature
        print("Signature:\n", signature.hex())

        print('─' * 10) 
        
        # Verify the signature
        is_valid = verify_signature(original_data, signature, public_key_path)
        print(f"Signature valid: {is_valid}")

        print('─' * 10) 

if __name__ == "__main__":
    main()