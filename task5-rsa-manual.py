# In this task, I apply Fermat's primality test to generate two large prime numbers for RSA key generation. Link to fermat primality test: https://en.wikipedia.org/wiki/Fermat_primality_test
# Explain general idea of my approach to the task here:

# Key Generation: Generate two large primes, calculate the modulus n and totient φ, then compute the public key e and private key d.
# Fermat's Primality Test: Ensure primes using a probabilistic test.
# Padding: Apply PKCS#1 v1.5 padding to secure the message.
# Encryption: Convert the padded message to an integer, then encrypt with the public key.
# Decryption: Decrypt using the private key and remove the padding to retrieve the original message.

# ChatGPT (August 8 Version), OpenAI. Accessed: October 11, 2024. [Online]. Available: https://chatgpt.com/share/6708db03-02d4-8008-a898-ee30494f1053

import random
from Crypto.Util.number import long_to_bytes, bytes_to_long
import math
import os

# a fix for making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Iterative Extended Euclidean Algorithm to avoid recursion depth issues
# This function calculates the greatest common divisor (GCD) of two numbers (a and b),
# and at the same time computes the coefficients for the equation ax + by = gcd(a, b).
# These coefficients help in calculating the modular inverse, which is essential in RSA decryption.
def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

# Function to compute modular inverse
# The modular inverse is needed to compute the private key d in RSA.
def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

# Fermat's primality test is used to check if a number is prime.
# It checks if a randomly chosen base 'a' satisfies Fermat's Little Theorem for prime numbers.
def fermat_is_prime(n, k=5):  # k = number of iterations for accuracy
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Perform k iterations to check primality using Fermat's Little Theorem
    i = 0
    while i < k:
        a = random.randint(2, n - 2) # Choose a random number in range [2, n-2]
        if pow(a, n - 1, n) != 1: # Fermat's little theorem: a^(n-1) ≡ 1 (mod n)
            return False
        i += 1
    return True

# This function generates a random prime number candidate of a given bit length.
# The number is made odd if it is even, and it is ensured that the number has at least 5 digits.
def generate_prime_candidate(length):
    # Ensure the generated number is at least 5 digits
    while True:
        p = random.getrandbits(length)
        # Make sure the number has at least 5 digits
        if p >= 10000:
            if p % 2 == 0:  # If the number is even, make it odd
                p += 1
            return p

# Function to generate a large prime number of the specified bit length
# This keeps generating prime candidates until one passes the Fermat primality test.
def generate_large_prime(length=512):
    p = generate_prime_candidate(length)
    while not fermat_is_prime(p):
        p = generate_prime_candidate(length)
    return p

# Built-in 'math.gcd' is used here to dynamically generate the public key exponent 'e'
# such that gcd(e, phi) = 1. This ensures that 'e' is coprime to phi.
# It then computes the corresponding private key exponent 'd' using the modular inverse function.
def generate_rsa_key(public_key_path, private_key_path, bit_length=512):
    p = generate_large_prime(bit_length)
    q = generate_large_prime(bit_length)

    n = p * q # RSA modulus
    phi = (p - 1) * (q - 1) # Euler's totient function

    # Dynamically generate e until gcd(e, phi) == 1
    while True:
        e = random.randrange(1, phi)  # Generate random e in a reasonable range
        if math.gcd(e, phi) == 1:  # Ensure that gcd(e, phi) = 1
            break
    
    # Compute the modular inverse
    d = mod_inverse(e, phi) # Compute the private key exponent d
    
    # Save the keys to files
    public_key = (e, n)
    private_key = (d, n)

    with open(public_key_path, "w") as f:
        f.write(f"{public_key}")
    with open(private_key_path, "w") as f:
        f.write(f"{private_key}")

    return public_key, private_key

# Add padding to the message (following the PKCS#1 v1.5 padding) before encryption.
def add_padding(message, n):
    message_bytes = message.encode()
    k = (n.bit_length() + 7) // 8  # The length of the modulus in bytes
    padding_length = k - len(message_bytes) - 3  # Calculate the padding length

    # Generate padding string (random non-zero bytes)
    padding_string = bytearray()
    while len(padding_string) < padding_length:
        byte = random.randint(1, 255)  # Generate random non-zero bytes for padding
        padding_string.append(byte)

    # Construct the padded message
    padded_message = b'\x00\x02' + bytes(padding_string) + b'\x00' + message_bytes
    return padded_message

# Encrypt the message by first padding it, then converting it to an integer,
# and finally performing RSA encryption using modular exponentiation.
def encrypt(file_path, public_key, output_file_path):
    e, n = public_key
    with open(file_path, "r") as f:
        message = f.read()

    # Add padding to the message
    padded_message = add_padding(message, n)

    # Convert padded message to integer
    message_int = bytes_to_long(padded_message)
    encrypted_message = pow(message_int, e, n)

    # Save the encrypted message to a file
    with open(output_file_path, "w") as f:
        f.write(str(encrypted_message))
    return encrypted_message

# Decrypt the message by reversing the RSA encryption process using the private key,
# removing padding, and converting the result back to a readable message.
def decrypt(encrypted_file_path, private_key, output_file_path):
    d, n = private_key
    with open(encrypted_file_path, "r") as f:
        encrypted_message = int(f.read())

    decrypted_int = pow(encrypted_message, d, n)
    
    # Ensure that the decrypted message has the correct byte length (matching the modulus size)
    k = (n.bit_length() + 7) // 8  # Length of the modulus in bytes
    decrypted_message_bytes = long_to_bytes(decrypted_int, k)  # Ensure full byte length, including leading 0x00 if necessary

    # Find the position of the 0x00 byte that separates the padding from the message
    message_start = decrypted_message_bytes.index(b'\x00', 2) + 1
    decrypted_message = decrypted_message_bytes[message_start:].decode()
    
    # Save the decrypted message to a file
    with open(output_file_path, "w") as f:
        f.write(decrypted_message)
    return decrypted_message

# Main function
def main():
    public_key_path = os.path.join(BASE, "keys", f"public_key_task5.txt")
    private_key_path = os.path.join(BASE, "keys", f"private_key_task5.txt")

    # Generate RSA keypair and store them in files
    public_key, private_key = generate_rsa_key(public_key_path, private_key_path, 512)

    # Define file paths using BASE for relative paths
    file_path = os.path.join(BASE, "input", "task5.txt")
    encrypted_file_path = os.path.join(BASE, "output", f"task5_enc.bin")
    decrypted_file_path = os.path.join(BASE, "output", f"task5_dec.txt")

    # Encrypt the message and save to file
    encrypt(file_path, public_key, encrypted_file_path)
    print(f"Cipher stored in {encrypted_file_path}")

    # Decrypt the message and save to file
    decrypt(encrypted_file_path, private_key, decrypted_file_path)
    print(f"Decrypted message stored in {decrypted_file_path}")

if __name__ == "__main__":
    main()
