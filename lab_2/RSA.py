#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep  7 17:44:43 2021

@author: christer
"""

import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Methods for encryption/decryption

def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

# We start by generatin the keys, the private key is kept secret
# and the publi key is given to peers communicated with.

# Generate a private key.
private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
)

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None)

public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend())

print(private_key_bytes)
print(public_key_bytes)


# THIS IS JUST FOR TRAINING (DO NOT USE THIS FOR REAL CRYPTOGRAPHY)

message = input("\nPlaintext: ").encode()

# Now let's encrypt the message using the publi key
message_as_int = bytes_to_int(message)
cipher_as_int = simple_rsa_encrypt(message_as_int, public_key)
cipher = int_to_bytes(cipher_as_int)
print("The encrypter message looks like this :", cipher)

#Let's see if we can get the text back
message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
message = int_to_bytes(message_as_int)
print("\nDecrypted messsage: {}\n".format(message))