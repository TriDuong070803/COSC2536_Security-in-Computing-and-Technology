# In this code, I use AES encryption with CBC mode and PKCS7 padding to securely encrypt a message before embedding it in an image using steganography. The key for encryption is derived using PBKDF2HMAC with SHA-256 and a random salt, based on a password provided by the user.
# The steps of the process are as follows:
# Step1: Encryption: The user’s message is encrypted using AES, where a salt and IV (Initialization Vector) are generated randomly for each session. The password is used to derive the encryption key through PBKDF2HMAC. 
# Step2: Steganography: due to the limitation of the lsb library, I have to write a function to convert jpeg/jpg to png and save png as binary. The encrypted message is then converted into a hex string and hidden within a PNG image using the LSB (Least Significant Bit) method provided by the stegano library.
# Step3: Extraction and Decryption: The hidden message is extracted from the image, converted back from its hex representation to bytes, and decrypted using the same password and salt.
# Step5: JPEG/JPG to PNG Conversion: Since the original image is in JPEG/JPG format, it is first converted to PNG before embedding the message. After processing, the PNG image is converted back to JPEG/JPG.


# The encrypt and decrypt code was developed from the base code (aes_cbc_file.py) from Lectorial (week 5, Lecture 5)
# The parts of the code that are inspired from lecture material are:

# Function to derive a key (PBKDF) & salting for added security
# Function to generate a key using the key derivation function (PBKDF) which is used to ensure a strong key is derived from the password
# Using salting for better, ehanced security
# Generating a random IV with CBC mode
# Adding PKCS7 padding
# Encrypting the message using AES in CBC mode
# Decrypting the message using AES in CBC mode


# ChatGPT (August 8 Version), OpenAI. Accessed: October 12, 2024. [Online]. Available: https://chatgpt.com/share/6709f77d-8048-8008-9855-ca9aabca63cf

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from stegano import lsb
from PIL import Image
import os
import io

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# AES encryption function
def encrypt_message(plaintext, password):
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key using PBKDF2HMAC with the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # A random IV is generated for each encryption session to ensure that 
    # encryption of the same data results in different ciphertexts.
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # AES operates on blocks of data, so PKCS7 padding is applied
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the salt, IV, and ciphertext
    return salt + iv + ciphertext

# AES decryption function
def decrypt_message(encrypted_data, password):
    # Extract the salt, IV, and ciphertext from the input
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    # Derive the key from the password using PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # Create AES cipher object in CBC mode for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Return the original plaintext message
    return plaintext.decode('utf-8')

# Function to hide the encrypted message in the image using stegano
def hide_message_in_image(png_binary, message):
    # Open the binary PNG as an image object
    img = Image.open(io.BytesIO(png_binary))
    
    # Hide the message using stegano's LSB functionality
    steg_img = lsb.hide(img, message)
    
    # Save the steg image to an in-memory binary stream
    output_bytes = io.BytesIO()
    steg_img.save(output_bytes, format="PNG")
    
    # Get the binary content of the stego image
    steg_png_binary = output_bytes.getvalue()
    
    # Close the buffer
    output_bytes.close()
    
    print(f"Message hidden in the image.")
    return steg_png_binary

# Function to extract the hidden message from the image using stegano
def extract_message_from_image(png_binary):
    # Load the binary PNG into an image object
    img = Image.open(io.BytesIO(png_binary))
    
    # Use stegano's LSB functionality to reveal the hidden message
    hidden_message = lsb.reveal(img)
    
    if hidden_message is None:
        raise ValueError("No hidden message found or message extraction failed.")
    
    return hidden_message

# Function to convert JPG to PNG binary and use it in the hiding process
def convert_jpg_to_png_binary(jpg_image_path):
    # Open the JPG image
    with Image.open(jpg_image_path) as img:
        # Convert the image to PNG format
        img = img.convert("RGB")
        
        # Save the image as PNG into an in-memory bytes buffer
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        
        # Get the binary content of the PNG image
        png_binary = img_bytes.getvalue()
        
        # Close the buffer
        img_bytes.close()
        
        return png_binary

# Function to convert a binary PNG back to a JPG image and save it
def convert_png_binary_to_jpg(png_binary, output_jpg_path):
    # Load the binary PNG content into an image object
    img = Image.open(io.BytesIO(png_binary))
    
    # Save the image as a JPG file
    img.save(output_jpg_path, "JPEG")
    print(f"Steganography image is saved at {output_jpg_path}")   

def main():
    # Ask user for input message
    message = input("Enter the message you want to hide: ")
    
    # password for encryption
    password = "s3924472"

    # Encrypt the message
    encrypted_message = encrypt_message(message, password)

    # Convert the encrypted message to a hex string for hiding in the image
    encrypted_message_str = encrypted_message.hex()
    
    # Hide the encrypted message in the image
    input_image_path = os.path.join(BASE, "input", "original_image.jpg")  # Path to your input JPG image
    output_image_path = os.path.join(BASE, "output", "stegano_image.jpg")  # Output image with hidden message
    
    # Convert JPG to PNG binary
    png_binary = convert_jpg_to_png_binary(input_image_path)
    
    # Step 1: Hide the encrypted message in the image
    steg_png_binary = hide_message_in_image(png_binary, encrypted_message_str)
    
    # Step 2: Extract the hidden message from the PNG image
    extracted_message_str = extract_message_from_image(steg_png_binary)

    # Convert the extracted string back to bytes
    extracted_message = bytes.fromhex(extracted_message_str)

    # Step 3: Decrypt the extracted message
    decrypted_message = decrypt_message(extracted_message, password)
    print("Decrypted message:", decrypted_message)
    
    # Step 4: Convert the PNG back to JPG after processing
    convert_png_binary_to_jpg(steg_png_binary, output_image_path)

if __name__ == "__main__":
    main()