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


# Setup public key logic

## Methods for encryption/decryption
def simple_rsa_encrypt(message, exponent, number):
    return gmpy2.powmod(message, exponent, number)

def simple_rsa_decrypt(cipher, exponent, number):
    return gmpy2.powmod(cipher, exponent, number)

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def generate_private_key(exponent, key_length):
    private_key = rsa.generate_private_key(
     public_exponent=exponent,
     key_size=key_length,
     backend=default_backend())
    return private_key

def generate_public_key(private_key):
  public_key = private_key.public_key()
  return public_key

# We start by generatin the keys, the private key is kept secret
# and the publi key is given to peers communicated with.

key_length = 4096
exponent = 65537

# Generate a private key.
private_key = generate_private_key(exponent, key_length);

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.TraditionalOpenSSL,
  encryption_algorithm=serialization.NoEncryption())

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)


print("\n === key length ===\n", key_length)
print("\n === public exponent ===\n", exponent)
print("\n === private key ===\n\n", private_key_bytes)
print("\n === public key ===\n\n", public_key_bytes)

# THIS IS JUST FOR TRAINING (DO NOT USE THIS FOR REAL CRYPTOGRAPHY)

message = input("\nPlaintext: ").encode()
message_as_int = bytes_to_int(message)

## ENCRYPTING WITH PUBLIC KEY
cipher_as_int = simple_rsa_encrypt(message_as_int, public_key.public_numbers().e, public_key.public_numbers().n)
cipher = int_to_bytes(cipher_as_int)
print("\n === Encrypted message ===\n", cipher)

# Let's see if we can get the text back
message_as_int = simple_rsa_decrypt(cipher_as_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
message = int_to_bytes(message_as_int)
print("\n === Decrypted messsage: {}\n".format(message))
